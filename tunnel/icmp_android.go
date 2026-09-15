//go:build android

package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The Android ping-socket carrier: SOCKET layer only.
//
// Everything testable lives in icmp_ping.go (no build tag, memory-testable on
// any host via the net.PacketConn seam). This file is what genuinely requires
// the Android kernel:
//
//   - socket(AF_INET[6], SOCK_DGRAM, IPPROTO_ICMP[v6]) — the unprivileged
//     ping socket, admitted by net.ipv4.ping_group_range (self-checked in
//     icmp_ping.go BEFORE any socket is created);
//   - handing the descriptor to protectFD immediately after creation and
//     BEFORE any traffic: a VpnService must exempt the fd or the Echo traffic
//     is captured by the app's own tunnel and loops until it dies;
//   - reading the kernel-assigned Echo Identifier out of getsockname(2) —
//     bionic's libc does not export getfsgid(2) either, which is why the
//     group self-check reads /proc/self/status instead.
//
// Role restriction: a ping socket is a client. It sends Echo Requests and
// receives the Replies addressed to its ident; an unprivileged socket cannot
// answer arbitrary Echo Requests, so a SERVER role on Android is refused here
// with a clear message rather than started and then silently deaf.

// newPlatformICMPTransport implements the platform seam for Android.
func newPlatformICMPTransport(cfg *icmpConfig) (platformICMP, error) {
	if cfg == nil || cfg.core == nil {
		return nil, errors.New("icmp: carrier configuration is required")
	}
	if cfg.role == icmpRoleServer {
		return nil, fmt.Errorf(
			"%w: Android's unprivileged ping socket can only be a CLIENT — "+
				"it cannot answer Echo Requests it did not solicit. "+
				"Run the server on a Linux host with the raw carrier",
			ErrTransportUnsupported)
	}
	if err := checkPingGroupRange(); err != nil {
		return nil, err
	}

	p := &pingICMP{
		in:       make(chan inboundEcho, pingPumpQueue),
		closed:   make(chan struct{}),
		sockPort: unixSockPort,
	}
	p.localName = "ping-socket/" + cfg.family.String()
	p.remoteName = cfg.peer.String()

	var openErrs []error
	if cfg.bindV4 {
		s, err := openPingSocket(4, cfg.protectFD)
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("ipv4: %w", err))
		} else {
			s.parent = p
			p.socks = append(p.socks, s)
		}
	}
	if cfg.bindV6 {
		s, err := openPingSocket(6, cfg.protectFD)
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("ipv6: %w", err))
		} else {
			s.parent = p
			p.socks = append(p.socks, s)
		}
	}
	if len(p.socks) == 0 {
		return nil, combineOpenErrors(openErrs)
	}
	if len(openErrs) > 0 && cfg.core.logger != nil {
		// A failed half under family "auto" is a degraded but working carrier;
		// saying so is the difference between "IPv6 is silently off" and an
		// operator knowing why.
		for _, err := range openErrs {
			cfg.core.logger.Warnf("[ICMP] %v; continuing with the families that did open", err)
		}
	}

	for _, s := range p.socks {
		p.pumps.Add(1)
		go p.pump(s)
	}
	return p, nil
}

// unixSockPort adapts getsockname(2) to the carrier's sockPort hook: on a ping
// socket the Echo Identifier IS the bound port, assigned by the kernel when
// the first datagram goes out.
func unixSockPort(fd int) (int, bool) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, false
	}
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return a.Port, true
	case *unix.SockaddrInet6:
		return a.Port, true
	default:
		return 0, false
	}
}

// openPingSocket creates one ping socket (SOCK_DGRAM + IPPROTO_ICMP[v6]) and
// hands the descriptor to protectFD immediately: a VpnService must exempt the
// descriptor BEFORE the first packet, or the Echo traffic is captured by the
// app's own tunnel and loops until it dies.
func openPingSocket(family int, protectFD func(fd int) error) (*pingSocket, error) {
	af, proto, name := unix.AF_INET, unix.IPPROTO_ICMP, "ping4"
	if family == 6 {
		af, proto, name = unix.AF_INET6, unix.IPPROTO_ICMPV6, "ping6"
	}
	fd, err := unix.Socket(af, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, interpretPingOpenError(err, family)
	}

	fail := func(format string, args ...any) (*pingSocket, error) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf(format, args...)
	}

	if err := unix.Bind(fd, wildcardSockaddr(family)); err != nil {
		return fail("icmp: binding the IPv%d ping socket failed: %w", family, err)
	}
	if protectFD != nil {
		if err := protectFD(fd); err != nil {
			return fail("icmp: protecting the carrier socket failed: %w", err)
		}
	}

	// Hand the descriptor to the runtime's netpoller. FilePacketConn duplicates
	// the descriptor (O_NONBLOCK lands on the dup) and classifies the socket by
	// its bound "port" (the ident) — which wraps it as a UDPConn, so
	// ReadFrom / WriteTo speak *net.UDPAddr, NOT the raw carrier's
	// *net.IPAddr; icmp_ping.go addresses its sends accordingly.
	file := os.NewFile(uintptr(fd), name)
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return fail("icmp: wrapping the IPv%d ping socket failed: %w", family, err)
	}
	_ = file.Close() // the runtime owns the duplicate now; the original fd is gone

	// Cleanup past this point must close the runtime's duplicate — the original
	// descriptor died with file.Close(), and closing its number again would
	// race any fd the runtime opened in between.
	fail = func(format string, args ...any) (*pingSocket, error) {
		_ = conn.Close()
		return nil, fmt.Errorf(format, args...)
	}

	// The sockPort hook reads the ident back out of getsockname and must
	// consult a descriptor that is still open. Everything above (protect
	// included) used the original, which file.Close() has just closed; the
	// runtime kept a duplicate, so re-resolve the live one for the hook.
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return fail("icmp: the wrapped IPv%d socket lost its syscall.Conn surface", family)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return fail("icmp: reaching the wrapped IPv%d descriptor failed: %w", family, err)
	}
	liveFD := -1
	if cerr := raw.Control(func(f uintptr) { liveFD = int(f) }); cerr != nil {
		return fail("icmp: reading the wrapped IPv%d descriptor failed: %v", family, cerr)
	}
	if liveFD <= 0 {
		return fail("icmp: the wrapped IPv%d socket reports descriptor %d", family, liveFD)
	}

	return &pingSocket{conn: conn, fd: liveFD, family: family}, nil
}

func wildcardSockaddr(family int) unix.Sockaddr {
	if family == 6 {
		return &unix.SockaddrInet6{Port: 0}
	}
	return &unix.SockaddrInet4{Port: 0}
}

// interpretPingOpenError turns a socket-creation failure into the actionable
// error. EACCES/EPERM here is almost always ping_group_range (already checked)
// or a SELinux policy the ROM ships.
func interpretPingOpenError(err error, family int) error {
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return fmt.Errorf(
			"%w: creating the IPv%d ping socket was denied. Check "+
				"net.ipv4.ping_group_range and the ROM's SELinux policy",
			ErrPingSocketDenied, family)
	case errors.Is(err, unix.EAFNOSUPPORT), errors.Is(err, unix.EPROTONOSUPPORT):
		return fmt.Errorf(
			"%w: this kernel has no IPv%d ping-socket support (socket() returned %v)",
			ErrTransportUnsupported, family, err)
	default:
		return fmt.Errorf("icmp: creating the IPv%d ping socket failed: %w", family, err)
	}
}
