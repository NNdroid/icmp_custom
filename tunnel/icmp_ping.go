package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// The Android ping-socket carrier: LOGIC layer.
//
// This file is deliberately free of build tags and of unix-syscall imports:
// everything here is driven through the net.PacketConn interface and two
// injected hooks, which is what makes the whole carrier memory-testable on
// ANY host (`go test` with a fake conn — no device, no root, no ICMP).
// icmp_android.go carries the only parts that truly need the Android kernel:
// creating the socket, binding it, handing the fd to protectFD, and reading
// the kernel-assigned identifier back out of getsockname.
//
// Recall what a ping socket gives an unprivileged app and what the kernel
// owns on its behalf:
//
//   - the IP header and the ICMP checksum are built by the kernel, so the
//     send path is checksum-free for BOTH families;
//   - the Echo Identifier IS the socket's bound "port": an unprivileged
//     sender may not stamp a foreign ident. The carrier therefore adopts the
//     kernel's assignment (read back via the sockPort hook after the first
//     send) and stamps that value on every subsequent probe;
//   - inbound datagrams are demultiplexed by ident, so the receive path sees
//     only traffic addressed to this socket — no filter needed.

const (
	pingReadBufSize = 65535
	pingPumpQueue   = 256

	pingTypeV4Request byte = 8
	pingTypeV4Reply   byte = 0
	pingTypeV6Request byte = 128
	pingTypeV6Reply   byte = 129
)

// pingGroupRangePath is where the kernel exposes the sysctl. A var (not a
// const) so tests can shadow it with a synthetic file.
var pingGroupRangePath = "/proc/sys/net/ipv4/ping_group_range"

// setPingGroupRangePath repoints the sysctl source; test-only.
func setPingGroupRangePath(p string) { pingGroupRangePath = p }

// pingSocket is one family's ping socket, seen from the logic layer.
type pingSocket struct {
	conn net.PacketConn
	fd   int
	// family is 4 or 6.
	family int
	// parent links back to the owning carrier (for the sockPort hook).
	parent *pingICMP

	// ident is the kernel-assigned Echo Identifier, valid once the first
	// datagram has gone out and refreshIdent has read it back.
	ident   uint16
	identMu sync.Mutex
}

// pingICMP is the carrier. Structurally a sibling of rawICMP: one pump
// goroutine per socket funnelling into a single receive channel.
type pingICMP struct {
	mu     sync.Mutex
	socks  []*pingSocket
	in     chan inboundEcho
	closed chan struct{}
	once   sync.Once
	pumps  sync.WaitGroup

	localName  string
	remoteName string

	// sockPort resolves the bound "port" (= Echo Identifier) of a socket fd.
	// Injected because the real implementation needs getsockname(2); tests
	// supply a fake. A port of 0 means "not assigned yet".
	sockPort func(fd int) (int, bool)
}

var _ platformICMP = (*pingICMP)(nil)

// checkPingGroupRange verifies the kernel would admit this app's groups to
// ping sockets BEFORE any socket is created, so the failure is a configuration
// error with the fix in the message instead of an EACCES from deep inside the
// first send. The sysctl's default "1 0" (min > max) means disabled.
//
// Everything here is os-level and portable: the Android file points
// pingGroupRangePath at procfs, and tests shadow it with a synthetic file.
func checkPingGroupRange() error {
	data, err := os.ReadFile(pingGroupRangePath)
	if err != nil {
		// No /proc (a hardened ROM, or a host OS without procfs): say nothing
		// and let the socket open attempt produce the real error.
		return nil
	}
	min, max, ok := parsePingGroupRange(string(data))
	if !ok {
		return nil // unparseable: let the socket open attempt decide
	}
	gid := os.Getgid()
	fsgid := selfFsgid(gid)
	groups, _ := os.Getgroups()

	admitted := func(g int) bool { return g >= min && g <= max }
	if admitted(gid) || admitted(fsgid) {
		return nil
	}
	for _, g := range groups {
		if admitted(g) {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: net.ipv4.ping_group_range = [%d %d] does not admit this app's groups "+
			"(gid %d, fsgid %d, supplementary %v). Grant it with "+
			"`sysctl -w net.ipv4.ping_group_range=\"%d %d\"` or equivalent, "+
			"or run the carrier as a group inside the range",
		ErrPingSocketDenied, min, max, gid, fsgid, groups, gid, gid)
}

// parsePingGroupRange parses the sysctl's "min max" pair.
func parsePingGroupRange(s string) (min, max int, ok bool) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return 0, 0, false
	}
	min, err1 := strconv.Atoi(fields[0])
	max, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return min, max, true
}

// procfsFsgid extracts the Fsgid from /proc/self/status. ok is false when
// procfs is unavailable or the Fsgid line is missing or unparseable.
func procfsFsgid() (int, bool) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Fsgid:"); ok {
			v, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// selfFsgid reads the effective filesystem GID from /proc/self/status. Android
// apps run with distinct gid/fsgid per package, and the kernel's ping socket
// permission check consults fsgid, not just gid. Bionic's libc does not export
// getfsgid(2), so the procfs value is the portable way to get it; falling back
// to gid keeps the check working on kernels without a readable status line.
func selfFsgid(fallback int) int {
	if v, ok := procfsFsgid(); ok {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

// pump reads one socket forever and forwards parsed messages to the shared
// channel. The kernel delivers only Echo messages addressed to this socket's
// ident (plus ICMP errors surfaced as read errors), so no filtering is needed
// here — that demultiplexing is the whole reason the ident is kernel-owned.
func (p *pingICMP) pump(s *pingSocket) {
	defer p.pumps.Done()
	buf := make([]byte, pingReadBufSize)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			if p.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			// Per-read errors on a ping socket are routinely transient (an
			// ICMP error queued for a probe that already gave up). Only a
			// closed socket ends the pump.
			continue
		}
		echo, ok := parseICMPMessage(buf[:n], s.family)
		if !ok {
			continue
		}
		if echo.PathBudget == 0 && len(echo.Payload) == 0 {
			continue
		}
		if peer := netipAddrOf(from); peer.IsValid() {
			echo.Path.Peer = netip.AddrPortFrom(peer, 0)
		} else {
			continue
		}
		// Report the ACTUAL identifier, not the one the request stamped: the
		// kernel owns the ident, and PathID is only useful when it mirrors
		// what is really on the wire.
		if id := s.localIdent(); id != 0 {
			echo.Path.Ident = id
		}
		// Copy out before queueing: buf is reused by the next read.
		if len(echo.Payload) > 0 {
			payload := make([]byte, len(echo.Payload))
			copy(payload, echo.Payload)
			echo.Payload = payload
		}
		select {
		case p.in <- echo:
		case <-p.closed:
			return
		}
	}
}

// localIdent returns the cached kernel-assigned identifier (0 until the first
// send made it known).
func (s *pingSocket) localIdent() uint16 {
	s.identMu.Lock()
	defer s.identMu.Unlock()
	return s.ident
}

// refreshIdent re-reads the bound "port" through the injected hook and caches
// it once non-zero.
func (s *pingSocket) refreshIdent() {
	if s.localIdent() != 0 {
		return
	}
	if s.parent == nil || s.parent.sockPort == nil {
		return
	}
	port, ok := s.parent.sockPort(s.fd)
	if !ok || port <= 0 || port > 0xffff {
		return
	}
	s.identMu.Lock()
	if s.ident == 0 {
		s.ident = uint16(port)
	}
	s.identMu.Unlock()
}

func (p *pingICMP) readEcho(buf []byte) (inboundEcho, error) {
	select {
	case echo, ok := <-p.in:
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
	case <-p.closed:
		return inboundEcho{}, ErrClosed
	}
}

// ---------------------------------------------------------------------------
// Send path
// ---------------------------------------------------------------------------

func (p *pingICMP) socketFor(addr netip.Addr) *pingSocket {
	want := 4
	if addr.Is6() && !addr.Is4In6() {
		want = 6
	}
	for _, s := range p.socks {
		if s.family == want {
			return s
		}
	}
	if len(p.socks) > 0 {
		return p.socks[0]
	}
	return nil
}

func (p *pingICMP) sendEcho(payload []byte, to netip.AddrPort, ident, seq uint16) error {
	// The kernel owns the ident: once assigned (after the first send), every
	// REQUEST must carry the kernel's value instead of the caller's. Until
	// then the caller's ident goes out as-is and the kernel adopts it.
	if s := p.socketFor(to.Addr()); s != nil {
		if id := s.localIdent(); id != 0 {
			ident = id
		}
	}
	return p.send(pingTypeV4Request, pingTypeV6Request, payload, to.Addr(), ident, seq)
}

func (p *pingICMP) sendEchoReply(payload []byte, path PathID) error {
	// Mirror the Identifier and sequence number EXACTLY as observed, including
	// zero — that is the platformICMP contract, and a NAT (or the peer)
	// expects its own values back. No ident takeover here: this is the one
	// direction where the local socket's ident is irrelevant. (On a ping
	// socket the kernel may refuse a foreign ident for an unprivileged
	// sender; that surfaces as a send error rather than silent corruption,
	// and in the client role replies are only sent when the server actively
	// pings us.)
	return p.send(pingTypeV4Reply, pingTypeV6Reply, payload, path.Peer.Addr(), path.Ident, path.Seq)
}

func (p *pingICMP) send(v4Type, v6Type byte, payload []byte, dst netip.Addr, ident, seq uint16) error {
	if p.isClosed() {
		return ErrClosed
	}
	if !dst.IsValid() {
		return fmt.Errorf("%w: no destination address", ErrNoRoute)
	}
	s := p.socketFor(dst)
	if s == nil {
		return fmt.Errorf("%w: the carrier has no open socket", ErrNoRoute)
	}

	var msgType byte = v4Type
	if s.family == 6 {
		msgType = v6Type
	}
	msg := buildEchoMessage(msgType, ident, seq, payload, false)
	addr := net.IPAddr{IP: dst.AsSlice()}
	if _, err := s.conn.WriteTo(msg, &addr); err != nil {
		return interpretPingSendError(err)
	}
	s.refreshIdent()
	return nil
}

// interpretPingSendError maps a send failure onto the profile's sentinels.
// EMSGSIZE means "the path refused this size", which the MTU search treats as
// a downward step rather than as loss. A ping socket surfaces kernel errnos
// wrapped in *net.OpError (the raw carrier sees them unwrapped), and the
// syscall-package constants used here carry the right per-platform values.
func interpretPingSendError(err error) error {
	if err == nil {
		return nil
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		if errors.Is(oe.Err, syscall.EMSGSIZE) {
			return fmt.Errorf("%w: the path refused an oversized packet: %v", ErrRecordTooLarge, err)
		}
		if errors.Is(oe.Err, syscall.ENETUNREACH) || errors.Is(oe.Err, syscall.EHOSTUNREACH) ||
			errors.Is(oe.Err, syscall.EACCES) {
			return fmt.Errorf("%w: %v", ErrNoRoute, err)
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func (p *pingICMP) localLabel() string  { return p.localName }
func (p *pingICMP) remoteLabel() string { return p.remoteName }

func (p *pingICMP) isClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

// close is idempotent and unblocks readEcho as well as every pump.
func (p *pingICMP) close() error {
	var first error
	p.once.Do(func() {
		close(p.closed)
		p.mu.Lock()
		for _, s := range p.socks {
			if err := s.conn.Close(); err != nil && first == nil {
				first = err
			}
		}
		p.mu.Unlock()
		p.pumps.Wait()
	})
	return first
}
