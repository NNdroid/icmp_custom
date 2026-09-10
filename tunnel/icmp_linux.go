//go:build linux && !android

package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

// The Linux raw-socket ICMP carrier: IPv4 and IPv6, both as SOCK_RAW.
//
// Raw sockets are used rather than the unprivileged ping socket because they
// are the only way to keep control of the Echo Identifier. A ping socket's
// Identifier is owned by the kernel (it IS the socket's bound port) and the
// kernel demultiplexes inbound replies by it, so a path that rewrites the
// Identifier — which plenty of NATs do — becomes unusable. The cost is
// CAP_NET_RAW, and that cost is paid here, loudly.
//
// A note on the two families' asymmetry, which drives most of this file:
//
//   - IPv4 delivers the IPv4 header ahead of the ICMP message, so it must be
//     stripped using the IHL field. IPv6 delivers the payload alone (RFC 3542).
//   - IPv4's checksum is ours to compute. IPv6's is computed BY THE KERNEL, and
//     IPV6_CHECKSUM is rejected with EINVAL at the IPPROTO_IPV6 level for an
//     ICMPv6 socket, so it must not be set. IPv6 is therefore the easier of the
//     two, which is the opposite of the folklore this project started with.
//   - An ICMPv6 raw socket receives every ICMPv6 message on the host — NDP,
//     router advertisements, MLD — because ICMPv6 is IPv4's ICMP, ARP and IGMP
//     combined. ICMP6_FILTER is not an optimisation here, it is what keeps the
//     receive path from being flooded. IPv4 gets ICMP_FILTER for the same
//     reason, minus the flood.
//   - IPv6 routers never fragment. An oversized packet is dropped and answered
//     with Packet Too Big, so automatic MTU discovery is a requirement there
//     rather than a nicety.

const (
	// rawReadBufSize is the largest possible IPv4/IPv6 datagram.
	rawReadBufSize = 65535

	// rawPumpQueue is how many inbound messages may wait for the session's
	// reader before the pump goroutine applies backpressure.
	rawPumpQueue = 256
)

// Protocol levels and socket options, spelled out with their names.
//
// They are stable Linux ABI values, and naming them here rather than importing
// them keeps this file independent of which constants a given dependency
// version happens to export. The transport takes only a handful of typed
// helpers from golang.org/x/sys/unix — two socket-option setters, the ICMPv6
// filter struct and the errno values — because the standard library's syscall
// package cannot express a struct-valued socket option on every architecture:
// linux/386 has no direct socket syscalls, only the legacy socketcall
// multiplexer.
const (
	protoIP     = 0  // IPPROTO_IP
	protoICMP   = 1  // IPPROTO_ICMP
	protoIPv6   = 41 // IPPROTO_IPV6
	protoICMPv6 = 58 // IPPROTO_ICMPV6

	optICMPFilter      = 1  // ICMP_FILTER, at level protoICMP
	optIPMTUDiscover   = 10 // IP_MTU_DISCOVER, at level protoIP
	optICMP6Filter     = 1  // ICMP6_FILTER, at level protoICMPv6
	optIPv6MTUDiscover = 23 // IPV6_MTU_DISCOVER, at level protoIPv6

	pmtudiscDo   = 2 // IP_PMTUDISC_DO
	pmtudiscDoV6 = 2 // IPV6_PMTUDISC_DO
)

// v4AllowedTypes is the ICMP_FILTER mask we want: echo reply, destination
// unreachable (which is where fragmentation-needed lives), echo request.
var v4AllowedTypes = []int{0, 3, 8}

// v6AllowedTypes is the ICMPv6 equivalent: Packet Too Big, echo request, echo
// reply. Everything else ICMPv6 exists to carry — neighbour discovery, router
// advertisements, MLD — is not ours and must not reach the receive path.
var v6AllowedTypes = []int{2, 128, 129}

// rawSocket is one family's raw ICMP socket.
type rawSocket struct {
	conn   *net.IPConn
	family int // 4 or 6
}

// rawICMP is the dual-stack carrier. In auto mode it owns two sockets and one
// pump goroutine per socket, funnelling both into a single receive channel so
// the session sees one stream regardless of family.
type rawICMP struct {
	mu     sync.Mutex
	socks  []*rawSocket
	in     chan inboundEcho
	closed chan struct{}
	once   sync.Once
	pumps  sync.WaitGroup

	localName  string
	remoteName string
}

var _ platformICMP = (*rawICMP)(nil)

// newPlatformICMPTransport implements the platform seam for Linux.
func newPlatformICMPTransport(cfg *icmpConfig) (platformICMP, error) {
	if cfg == nil || cfg.core == nil {
		return nil, errors.New("icmp: carrier configuration is required")
	}

	r := &rawICMP{
		in:     make(chan inboundEcho, rawPumpQueue),
		closed: make(chan struct{}),
	}
	r.localName = "raw-icmp/" + cfg.family.String()
	r.remoteName = "any"
	if cfg.role == icmpRoleClient {
		r.remoteName = cfg.peer.String()
	}

	var openErrs []error
	if cfg.bindV4 {
		s, err := openRawSocket("ip4:icmp", "0.0.0.0", 4, cfg.protectFD)
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("ipv4: %w", err))
		} else {
			r.socks = append(r.socks, s)
		}
	}
	if cfg.bindV6 {
		s, err := openRawSocket("ip6:ipv6-icmp", "::", 6, cfg.protectFD)
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("ipv6: %w", err))
		} else {
			r.socks = append(r.socks, s)
		}
	}

	if len(r.socks) == 0 {
		return nil, combineOpenErrors(openErrs)
	}
	if len(openErrs) > 0 && cfg.core.logger != nil {
		// A forced family that failed is fatal (handled above). A family that
		// failed under "auto" is a degraded but working carrier, and saying so
		// is the difference between "IPv6 is silently off" and an operator
		// knowing why.
		for _, err := range openErrs {
			cfg.core.logger.Warnf("[ICMP] %v; continuing with the families that did open", err)
		}
	}

	for _, s := range r.socks {
		r.pumps.Add(1)
		go r.pump(s)
	}
	return r, nil
}

// combineOpenErrors, netipAddrOf, buildEchoMessage, icmpv4Checksum and
// parseICMPMessage live in icmp_echo.go, shared with the Android ping-socket
// carrier; only the raw-socket specifics remain in this file.

// openRawSocket creates one raw ICMP socket and applies the options the profile
// depends on. Every failure path is explicit: a raw socket that cannot be
// created must say why and what to do, never quietly become a no-op.
func openRawSocket(network, address string, family int, protectFD func(fd int) error) (*rawSocket, error) {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, interpretRawOpenError(err, family)
	}
	ipc, ok := conn.(*net.IPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %s did not yield a raw IP socket", ErrTransportUnsupported, network)
	}

	s := &rawSocket{conn: ipc, family: family}

	raw, err := ipc.SyscallConn()
	if err != nil {
		_ = ipc.Close()
		return nil, fmt.Errorf("icmp: cannot reach the socket descriptor: %w", err)
	}
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		if protectFD != nil {
			// Android's VpnService needs to exempt this descriptor from its own
			// tunnel. On desktop the callback is nil and this is a no-op.
			if err := protectFD(int(fd)); err != nil {
				optErr = fmt.Errorf("icmp: protecting the carrier socket failed: %w", err)
				return
			}
		}
		optErr = s.applyOptions(int(fd))
	}); err != nil {
		_ = ipc.Close()
		return nil, fmt.Errorf("icmp: socket control failed: %w", err)
	}
	if optErr != nil {
		_ = ipc.Close()
		return nil, optErr
	}
	return s, nil
}

// applyOptions is best-effort for the filters and mandatory for MTU discovery.
//
// The filters keep unrelated ICMP out of the receive path. They are not a
// correctness requirement — parse() already ignores anything that is not an
// Echo or a path-MTU report — but on IPv6 they are the difference between
// reading a handful of messages and reading every piece of neighbour discovery,
// router advertisement and MLD traffic on the host. A rejected filter therefore
// degrades to software filtering instead of failing the socket.
//
// IP_MTU_DISCOVER is different, and its failure IS fatal: without "do not
// fragment" the kernel silently fragments an oversized packet, a CGNAT drops
// the fragments, and the automatic MTU search loses the only precise signal it
// ever gets. A socket that cannot report EMSGSIZE is a socket whose MTU search
// is blind, and a blind MTU search fails silently at exactly the wrong moment.
func (s *rawSocket) applyOptions(fd int) error {
	switch s.family {
	case 4:
		// ICMP_FILTER is a single 32-bit type mask, so the integer setter is
		// exactly right; the kernel reads four bytes of the option value.
		var mask int
		for _, t := range v4AllowedTypes {
			mask |= 1 << uint(t)
		}
		_ = unix.SetsockoptInt(fd, protoICMP, optICMPFilter, mask)
		if err := unix.SetsockoptInt(fd, protoIP, optIPMTUDiscover, pmtudiscDo); err != nil {
			return fmt.Errorf("%w: cannot enable IPv4 PMTU discovery (IP_MTU_DISCOVER): %v", ErrTransportUnsupported, err)
		}
	case 6:
		f := &unix.ICMPv6Filter{}
		for _, t := range v6AllowedTypes {
			f.Data[t/32] |= 1 << uint(t%32)
		}
		_ = unix.SetsockoptICMPv6Filter(fd, protoICMPv6, optICMP6Filter, f)
		if err := unix.SetsockoptInt(fd, protoIPv6, optIPv6MTUDiscover, pmtudiscDoV6); err != nil {
			return fmt.Errorf("%w: cannot enable IPv6 PMTU discovery (IPV6_MTU_DISCOVER): %v", ErrTransportUnsupported, err)
		}
	default:
		return fmt.Errorf("%w: unknown socket family %d", ErrTransportUnsupported, s.family)
	}
	return nil
}

// interpretRawOpenError turns a socket-creation failure into the actionable
// error the operator needs. Silent degradation is explicitly forbidden here: a
// tunnel that reports success and then carries nothing is worse than one that
// refuses to start.
func interpretRawOpenError(err error, family int) error {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf(
			"%w: opening the IPv%d raw socket was denied. Grant it with "+
				"`sudo setcap cap_net_raw+ep <binary>`, or run as root",
			ErrNoCapNetRaw, family)
	case errors.Is(err, unix.EAFNOSUPPORT), errors.Is(err, unix.EPROTONOSUPPORT):
		return fmt.Errorf(
			"%w: this host has no usable IPv%d support (socket() returned %v)",
			ErrTransportUnsupported, family, err)
	default:
		return fmt.Errorf("icmp: opening the IPv%d raw socket failed: %w", family, err)
	}
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

// pump reads one socket forever and forwards parsed messages to the shared
// channel. One goroutine per family is what lets a single Transport serve a
// dual-stack server without an epoll loop.
func (r *rawICMP) pump(s *rawSocket) {
	defer r.pumps.Done()
	buf := make([]byte, rawReadBufSize)
	for {
		n, from, err := s.conn.ReadFromIP(buf)
		if err != nil {
			if r.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			// A per-read error on a raw socket is routinely transient (a
			// queued ICMP error for a socket that has gone, an oversized
			// datagram). Only a closed socket ends the pump.
			continue
		}
		echo, ok := s.parse(buf[:n])
		if !ok {
			continue
		}
		if echo.PathBudget == 0 && len(echo.Payload) == 0 {
			continue
		}
		// The source address is the only place the peer is knowable: IPv6 raw
		// sockets are handed the payload WITHOUT an IPv6 header, and IPv4's
		// header is stripped inside parse. ICMP has no ports, so the port is
		// the zero placeholder.
		if peer := netipAddrOf(from); peer.IsValid() {
			echo.Path.Peer = netip.AddrPortFrom(peer, 0)
		} else {
			continue
		}
		// Copy out before queueing: buf is reused by the next read.
		if len(echo.Payload) > 0 {
			payload := make([]byte, len(echo.Payload))
			copy(payload, echo.Payload)
			echo.Payload = payload
		}
		select {
		case r.in <- echo:
		case <-r.closed:
			return
		}
	}
}

// parse decodes one received datagram into an inboundEcho. It reports false for
// anything that is neither an Echo we can use nor a path-MTU report.
func (s *rawSocket) parse(raw []byte) (inboundEcho, bool) {
	msg := raw
	if s.family == 4 {
		// A raw IPv4 socket is handed the IPv4 header ahead of the ICMP
		// message; strip it using the IHL field (which may exceed 20 for
		// options).
		if len(raw) < 20 {
			return inboundEcho{}, false
		}
		ihl := int(raw[0]&0x0f) * 4
		if ihl < 20 || ihl > len(raw) {
			return inboundEcho{}, false
		}
		msg = raw[ihl:]
	}
	return parseICMPMessage(msg, s.family)
}

// readEcho implements platformICMP. A payload larger than buf is a hard error,
// never a truncation: a truncated record would fail its AEAD tag and look like
// a forgery.
func (r *rawICMP) readEcho(buf []byte) (inboundEcho, error) {
	select {
	case echo, ok := <-r.in:
		if !ok {
			return inboundEcho{}, ErrClosed
		}
		if len(echo.Payload) > len(buf) {
			return inboundEcho{}, fmt.Errorf("%w: record is %d bytes, buffer is %d",
				ErrRecordTooLarge, len(echo.Payload), len(buf))
		}
		n := copy(buf, echo.Payload)
		if n > 0 {
			echo.Payload = buf[:n]
		} else {
			echo.Payload = nil
		}
		return echo, nil
	case <-r.closed:
		return inboundEcho{}, ErrClosed
	}
}

// ---------------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------------

// socketFor picks the socket for a destination address. The family is a
// property of the address, so a dual-stack carrier never has to guess.
func (r *rawICMP) socketFor(addr netip.Addr) *rawSocket {
	want := 4
	if addr.Is6() && !addr.Is4In6() {
		want = 6
	}
	for _, s := range r.socks {
		if s.family == want {
			return s
		}
	}
	// Fall back to whatever exists; send will fail with the natural error
	// rather than silently doing nothing.
	if len(r.socks) > 0 {
		return r.socks[0]
	}
	return nil
}

func (r *rawICMP) sendEcho(payload []byte, to netip.AddrPort, ident, seq uint16) error {
	return r.send(8, 128, payload, to.Addr(), ident, seq)
}

func (r *rawICMP) sendEchoReply(payload []byte, path PathID) error {
	// Mirror the Identifier and sequence number EXACTLY as observed, including
	// zero. A NAT that rewrote them expects its own values back, and a peer
	// that chose zero chose it deliberately.
	return r.send(0, 129, payload, path.Peer.Addr(), path.Ident, path.Seq)
}

func (r *rawICMP) send(v4Type, v6Type byte, payload []byte, dst netip.Addr, ident, seq uint16) error {
	if r.isClosed() {
		return ErrClosed
	}
	if !dst.IsValid() {
		return fmt.Errorf("%w: no destination address", ErrNoRoute)
	}
	s := r.socketFor(dst)
	if s == nil {
		return fmt.Errorf("%w: the carrier has no open socket", ErrNoRoute)
	}
	addr := net.IPAddr{IP: dst.AsSlice()}

	if s.family == 4 {
		msg := buildEchoMessage(v4Type, ident, seq, payload, true)
		_, err := s.conn.WriteToIP(msg, &addr)
		return interpretSendError(err)
	}
	msg := buildEchoMessage(v6Type, ident, seq, payload, false)
	_, err := s.conn.WriteToIP(msg, &addr)
	return interpretSendError(err)
}

// interpretSendError maps a send failure onto the profile's sentinels. MSGSIZE
// is the interesting one: with IP_PMTUDISC_DO it means "the path refused this
// size", which the MTU search treats as a downward step rather than as loss.
func interpretSendError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EMSGSIZE) {
		return fmt.Errorf("%w: the path refused an oversized packet: %v", ErrRecordTooLarge, err)
	}
	if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
		return fmt.Errorf("%w: %v", ErrNoRoute, err)
	}
	return err
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func (r *rawICMP) localLabel() string  { return r.localName }
func (r *rawICMP) remoteLabel() string { return r.remoteName }

func (r *rawICMP) isClosed() bool {
	select {
	case <-r.closed:
		return true
	default:
		return false
	}
}

// close is idempotent and unblocks readEcho as well as both pumps.
func (r *rawICMP) close() error {
	var first error
	r.once.Do(func() {
		close(r.closed)
		r.mu.Lock()
		for _, s := range r.socks {
			if err := s.conn.Close(); err != nil && first == nil {
				first = err
			}
		}
		r.mu.Unlock()
		r.pumps.Wait()
	})
	return first
}
