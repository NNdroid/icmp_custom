package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The Android ping-socket carrier, tested IN MEMORY.
//
// icmp_ping.go is driven entirely through the net.PacketConn interface and an
// injected sockPort hook, so every behaviour below — the pump, the ident
// takeover, the checksum-free wire format, the error mapping, the
// ping_group_range self-check — runs on ANY host with no device, no root and
// no ICMP. Only the real syscalls (openPingSocket) need a device, and those
// get a device-gated test in icmp_ping_device_test.go.
// ---------------------------------------------------------------------------

// fakePingConn is a net.PacketConn standing in for the kernel socket: writes
// are recorded, reads come from a test-fed queue.
type fakePingConn struct {
	mu       sync.Mutex
	written  [][]byte
	addrs    []net.Addr
	inbound  chan []byte
	closed   chan struct{}
	closeOne sync.Once
}

func newFakePingConn() *fakePingConn {
	return &fakePingConn{inbound: make(chan []byte, 16), closed: make(chan struct{})}
}

func (c *fakePingConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case raw := <-c.inbound:
		// The real ping socket is wrapped as a UDPConn (the runtime classifies
		// it by its bound ident "port"), so ReadFrom reports the peer as a
		// *net.UDPAddr — mirror that here to keep the fake honest.
		return copy(buf, raw), &net.UDPAddr{IP: net.ParseIP("203.0.113.7")}, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakePingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), b...))
	c.addrs = append(c.addrs, addr)
	return len(b), nil
}

func (c *fakePingConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return nil
}

func (c *fakePingConn) LocalAddr() net.Addr { return &net.IPAddr{} }

// Deadline methods: part of net.PacketConn. The carrier never sets them (the
// pacer and RTO logic live above the socket), but the interface demands them.
func (c *fakePingConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakePingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakePingConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *fakePingConn) lastWrite(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.written) == 0 {
		t.Fatal("nothing was written to the socket")
	}
	return c.written[len(c.written)-1]
}

// newMemPingCarrier builds the carrier on fake sockets. sockPort simulates the
// kernel: the first datagram is what makes getsockname report the assignment,
// so the hook returns the configured ident from its first call onward (a zero
// ident simulates a socket the kernel has not yet bound).
func newMemPingCarrier(t *testing.T, ident uint16) (*pingICMP, *fakePingConn, *pingSocket) {
	t.Helper()
	conn := newFakePingConn()
	p := &pingICMP{
		in:     make(chan inboundEcho, pingPumpQueue),
		closed: make(chan struct{}),
		sockPort: func(int) (int, bool) {
			return int(ident), ident != 0
		},
	}
	s := &pingSocket{conn: conn, fd: 7, family: 4, parent: p}
	p.socks = []*pingSocket{s}
	p.pumps.Add(1)
	go p.pump(s)
	t.Cleanup(func() { _ = p.close() })
	return p, conn, s
}

func TestPingSendEchoFirstProbeStampsTheRequestedIdent(t *testing.T) {
	p, conn, _ := newMemPingCarrier(t, 0x4000)

	if err := p.sendEcho([]byte("probe-1"), netip.MustParseAddrPort("203.0.113.7:0"), 0x1234, 9); err != nil {
		t.Fatalf("sendEcho: %v", err)
	}
	msg := conn.lastWrite(t)
	if msg[0] != pingTypeV4Request {
		t.Fatalf("message type = %d, want Echo Request", msg[0])
	}
	// Checksum-free wire format: a ping socket's kernel builds it.
	if binary.BigEndian.Uint16(msg[2:4]) != 0 {
		t.Fatal("the checksum field must be left for the kernel")
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 0x1234 {
		t.Fatalf("first probe ident = %#x, want the requested 0x1234", got)
	}
	if binary.BigEndian.Uint16(msg[6:8]) != 9 {
		t.Fatal("seq must round-trip")
	}
	if string(msg[8:]) != "probe-1" {
		t.Fatalf("payload = %q", msg[8:])
	}
}

func TestPingSendEchoAdoptsTheKernelIdentAfterAssignment(t *testing.T) {
	// The kernel assigns ident 0x4000; the SECOND probe must carry it, not
	// the caller-requested one, and the checksum field must stay zero.
	p, conn, _ := newMemPingCarrier(t, 0x4000)

	_ = p.sendEcho([]byte("one"), netip.MustParseAddrPort("203.0.113.7:0"), 0x1234, 1)
	_ = p.sendEcho([]byte("two"), netip.MustParseAddrPort("203.0.113.7:0"), 0x1234, 2)

	msg := conn.lastWrite(t)
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 0x4000 {
		t.Fatalf("second probe ident = %#x, want the kernel-assigned 0x4000", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0 {
		t.Fatal("the checksum field must stay kernel-owned on every probe")
	}
}

func TestPingSendEchoReplyMirrorsTheObservedPath(t *testing.T) {
	p, conn, s := newMemPingCarrier(t, 0)
	// Pretend the kernel already assigned 0x5060: a reply must mirror the
	// path the peer observed, NOT the local ident.
	s.ident = 0x5060

	path := PathID{
		Peer:  netip.MustParseAddrPort("203.0.113.7:0"),
		Ident: 0x0F0E,
		Seq:   77,
	}
	if err := p.sendEchoReply([]byte("downlink"), path); err != nil {
		t.Fatalf("sendEchoReply: %v", err)
	}
	msg := conn.lastWrite(t)
	if msg[0] != pingTypeV4Reply {
		t.Fatalf("message type = %d, want Echo Reply", msg[0])
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 0x0F0E {
		t.Fatalf("reply ident = %#x, want the mirrored 0x0F0E", got)
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != 77 {
		t.Fatalf("reply seq = %d, want 77", got)
	}
}

func TestPingPumpOverridesThePathIdentWithTheKernelAssignment(t *testing.T) {
	p, conn, s := newMemPingCarrier(t, 0)
	s.ident = 0x4000 // the kernel assignment, as read back from getsockname

	// An inbound Echo Reply carrying the peer's view of the ident. The wire
	// ident is what NATs rewrite; PathID must report the kernel's truth.
	wire := buildEchoMessage(pingTypeV4Reply, 0x1234, 42, []byte("record"), false)
	conn.inbound <- wire

	echo, err := p.readEcho(make([]byte, testRecordLimit))
	if err != nil {
		t.Fatalf("readEcho: %v", err)
	}
	if string(echo.Payload) != "record" {
		t.Fatalf("payload = %q", echo.Payload)
	}
	if echo.IsRequest {
		t.Fatal("type 0 must not be a request")
	}
	if echo.Path.Ident != 0x4000 {
		t.Fatalf("path ident = %#x, want the kernel-assigned 0x4000", echo.Path.Ident)
	}
	if echo.Path.Seq != 42 || echo.Path.Peer.Addr().String() != "203.0.113.7" {
		t.Fatalf("path = %+v", echo.Path)
	}
}

func TestPingPumpDropsJunkAndBudgetOnlyMessagesReachReadEcho(t *testing.T) {
	p, conn, _ := newMemPingCarrier(t, 0)

	// Junk first, then a bare frag-needed report (PathBudget, no payload),
	// then a real record. The frag-needed report is NOT junk: it is the MTU
	// search's only precise downward signal, so it is queued too — and it
	// arrives FIRST, before the record behind it.
	conn.inbound <- []byte{99, 0, 0, 0, 0, 0, 0, 0} // unknown type: dropped
	frag := make([]byte, 8)
	frag[0], frag[1] = 3, 4
	binary.BigEndian.PutUint16(frag[6:8], 1400)
	conn.inbound <- frag
	conn.inbound <- buildEchoMessage(pingTypeV4Reply, 1, 2, []byte("real"), false)

	budget, err := p.readEcho(make([]byte, testRecordLimit))
	if err != nil {
		t.Fatalf("readEcho (budget): %v", err)
	}
	if budget.PathBudget != 1400-ipv4HeaderOverhead || len(budget.Payload) != 0 {
		t.Fatalf("budget message = %+v, want the frag-needed path budget", budget)
	}
	echo, err := p.readEcho(make([]byte, testRecordLimit))
	if err != nil {
		t.Fatalf("readEcho (record): %v", err)
	}
	if string(echo.Payload) != "real" {
		t.Fatalf("junk reached the session: payload=%q", echo.Payload)
	}
}

func TestPingSocketForPicksTheFamilyAndFallsBack(t *testing.T) {
	conn := newFakePingConn()
	p := &pingICMP{closed: make(chan struct{})}
	v4 := &pingSocket{conn: conn, family: 4, parent: p}
	p.socks = []*pingSocket{v4}

	if got := p.socketFor(netip.MustParseAddr("2001:db8::1")); got != v4 {
		t.Fatal("with only a v4 socket, a v6 destination must fall back to it")
	}
	if got := p.socketFor(netip.MustParseAddr("192.0.2.1")); got != v4 {
		t.Fatal("a v4 destination must pick the v4 socket")
	}

	// A closed carrier answers sends with ErrClosed rather than a write.
	_ = p.close()
	if err := p.sendEcho([]byte("x"), netip.MustParseAddrPort("192.0.2.1:0"), 1, 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("send on a closed carrier = %v, want ErrClosed", err)
	}
}

func TestPingCloseUnblocksReadEcho(t *testing.T) {
	p, _, _ := newMemPingCarrier(t, 0)

	done := make(chan error, 1)
	go func() {
		_, err := p.readEcho(make([]byte, testRecordLimit))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = p.close()

	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("readEcho after close = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not unblock readEcho")
	}
}

func TestPingSendRejectsAnInvalidDestination(t *testing.T) {
	p, _, _ := newMemPingCarrier(t, 0)
	if err := p.sendEcho([]byte("x"), netip.MustParseAddrPort("192.0.2.1:0"), 1, 1); err != nil {
		t.Fatalf("a valid destination must be sendable: %v", err)
	}
	if err := p.sendEcho([]byte("x"), netip.AddrPortFrom(netip.Addr{}, 0), 1, 1); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("a zero address = %v, want ErrNoRoute", err)
	}
}

func TestInterpretPingSendErrorMapsTheProfileSentinels(t *testing.T) {
	if err := interpretPingSendError(nil); err != nil {
		t.Fatalf("nil = %v, want nil", err)
	}
	// Ping sockets surface kernel errnos wrapped in *net.OpError, unlike the
	// raw carrier which sees them unwrapped. The syscall constants used here
	// carry per-platform values, so this mapping holds on every host.
	op := &net.OpError{Op: "write", Err: syscall.EMSGSIZE}
	if err := interpretPingSendError(op); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("EMSGSIZE = %v, want ErrRecordTooLarge", err)
	}
	for _, errno := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EACCES} {
		op := &net.OpError{Op: "write", Err: errno}
		if err := interpretPingSendError(op); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("%v = %v, want ErrNoRoute", errno, err)
		}
	}
	if err := interpretPingSendError(errors.New("transient")); err == nil || errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("an unrelated error must pass through unchanged, got %v", err)
	}
}

// TestPingPumpEndsWhenTheConnCloses proves the pump goroutine terminates: a
// leaked pump would hold the wait group and hang close().
func TestPingPumpEndsWhenTheConnCloses(t *testing.T) {
	p, conn, _ := newMemPingCarrier(t, 0)
	p.pumps.Add(1)
	go p.pump(p.socks[0])

	_ = conn.Close()
	finished := make(chan struct{})
	go func() { p.pumps.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the pump did not end after the conn closed")
	}
}

// ---------------------------------------------------------------------------
// The ping_group_range self-check: pure file logic, shadowed sysctl.
// ---------------------------------------------------------------------------

func TestParsePingGroupRange(t *testing.T) {
	cases := []struct {
		in          string
		min, max    int
		ok          bool
		description string
	}{
		{"1\t0", 1, 0, true, "the kernel default: min > max means disabled"},
		{"0 2147483647", 0, 2147483647, true, "the permissive setting most guides recommend"},
		{"  100   200  ", 100, 200, true, "whitespace must not matter"},
		{"999 4294967295", 999, 4294967295, true, "large upper bounds parse"},
		{"garbage", 0, 0, false, "one field is not a range"},
		{"1 2 3", 0, 0, false, "three fields is not a range"},
		{"a b", 0, 0, false, "non-numeric fields are not a range"},
		{"", 0, 0, false, "empty input"},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			min, max, ok := parsePingGroupRange(tc.in)
			if ok != tc.ok || (ok && (min != tc.min || max != tc.max)) {
				t.Fatalf("parsePingGroupRange(%q) = %d, %d, %t; want %d, %d, %t",
					tc.in, min, max, ok, tc.min, tc.max, tc.ok)
			}
		})
	}
}

func TestSelfFsgidFallsBackWithoutProcfs(t *testing.T) {
	// Hosts without /proc/self/status (Windows, macOS) must fall back to the
	// caller's value rather than zero or panic.
	if fsgid := selfFsgid(4242); fsgid != 4242 {
		t.Fatalf("selfFsgid with no procfs = %d, want the fallback 4242", fsgid)
	}
	// On procfs hosts the real Fsgid must win — but only when the status file
	// actually carries a parseable Fsgid line. Sandboxes may expose
	// /proc/self/status without one, and returning the fallback (the -1
	// sentinel here) is the correct answer for exactly that case.
	if _, ok := procfsFsgid(); !ok {
		t.Skip("no /proc/self/status with a parseable Fsgid on this host")
	}
	if fsgid := selfFsgid(-1); fsgid < 0 {
		t.Fatalf("selfFsgid from procfs = %d, out of range", fsgid)
	}
}

func TestCheckPingGroupRangeAgainstASyntheticSysctl(t *testing.T) {
	gid := os.Getgid()
	fsgid := selfFsgid(gid)
	groups, _ := os.Getgroups()

	// Mirror of the kernel's admission rule, used to compute the expectation:
	// on Windows os.Getgid() reports -1, so "the permissive range admits"
	// cannot be assumed a priori — the expectation must be derived.
	admits := func(lo, hi int) bool {
		in := func(g int) bool { return g >= lo && g <= hi }
		if in(gid) || in(fsgid) {
			return true
		}
		for _, g := range groups {
			if in(g) {
				return true
			}
		}
		return false
	}
	expect := func(wantAdmitted bool) {
		t.Helper()
		err := checkPingGroupRange()
		if gotAdmitted := err == nil; gotAdmitted != wantAdmitted {
			t.Fatalf("checkPingGroupRange = %v, want admitted=%t (gid=%d fsgid=%d groups=%v)",
				err, wantAdmitted, gid, fsgid, groups)
		}
		if err != nil && !errors.Is(err, ErrPingSocketDenied) {
			t.Fatalf("a refusal must wrap ErrPingSocketDenied, got %v", err)
		}
	}
	shadow := func(content string) (restore func()) {
		tmp := filepath.Join(t.TempDir(), "ping_group_range")
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		orig := pingGroupRangePath
		setPingGroupRangePath(tmp)
		return func() { setPingGroupRangePath(orig) }
	}

	// The disabled default refuses everyone, on every platform.
	restore := shadow("1\t0")
	expect(false)
	restore()

	// A range covering exactly the fsgid admits the process.
	restore = shadow(fmt.Sprintf("%d %d", fsgid, fsgid))
	expect(admits(fsgid, fsgid))
	restore()

	// A range covering exactly one supplementary group admits too.
	if len(groups) > 0 {
		restore = shadow(fmt.Sprintf("%d %d", groups[0], groups[0]))
		expect(admits(groups[0], groups[0]))
		restore()
	}

	// The permissive setting most guides recommend.
	restore = shadow("0 2147483647")
	expect(admits(0, 2147483647))
	restore()

	// An unparseable sysctl defers to the socket open attempt.
	restore = shadow("banana")
	if err := checkPingGroupRange(); err != nil {
		t.Fatalf("an unparseable sysctl must not hard-fail the check: %v", err)
	}
	restore()

	// A missing file defers to the socket open attempt.
	setPingGroupRangePath(filepath.Join(t.TempDir(), "does-not-exist"))
	if err := checkPingGroupRange(); err != nil {
		t.Fatalf("a missing sysctl must not hard-fail the check: %v", err)
	}
	setPingGroupRangePath("/proc/sys/net/ipv4/ping_group_range")
}

func TestCheckPingGroupRangeRefusalCarriesTheFix(t *testing.T) {
	gid := os.Getgid()
	groups, _ := os.Getgroups()
	shadow := func(content string) (restore func()) {
		tmp := filepath.Join(t.TempDir(), "ping_group_range")
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		orig := pingGroupRangePath
		setPingGroupRangePath(tmp)
		return func() { setPingGroupRangePath(orig) }
	}
	// A range that admits nobody: strictly above every group this process
	// actually has. Deriving it as gid+100/gid+200 is NOT enough — CI runners
	// (macOS in particular) carry supplementary groups far above the primary
	// gid (e.g. _developer, GID 204), and one landing inside the synthesized
	// range flips the expectation to "admitted".
	maxGroup := 0
	for _, g := range append([]int{gid, selfFsgid(gid)}, groups...) {
		if g > maxGroup {
			maxGroup = g
		}
	}
	if maxGroup > (1<<31)-201 {
		t.Skip("group ids too large to synthesize an excluding range")
	}
	restore := shadow(fmt.Sprintf("%d %d", maxGroup+100, maxGroup+200))
	err := checkPingGroupRange()
	restore()
	if !errors.Is(err, ErrPingSocketDenied) {
		t.Fatalf("an out-of-range gid must refuse: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"ping_group_range", "sysctl -w", "fsgid"} {
		if !bytes.Contains([]byte(msg), []byte(want)) {
			t.Fatalf("the refusal must mention %q: %q", want, msg)
		}
	}
}
