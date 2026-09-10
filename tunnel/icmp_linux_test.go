//go:build linux && !android

package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// The Linux raw-socket carrier: the socket-specific surface.
//
// The pure wire-format tests live in icmp_echo_test.go with no build tag, so
// they run on every host. Only what touches the raw socket itself stays here.
// ---------------------------------------------------------------------------

func TestRawSocketParseStripsTheIPv4Header(t *testing.T) {
	icmp := buildEchoMessage(0, 0x1111, 0x2222, []byte("inside"), true)

	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, IHL = 5 (20 bytes)
	raw := append(ip, icmp...)

	s := &rawSocket{family: 4}
	echo, ok := s.parse(raw)
	if !ok {
		t.Fatal("a well-formed IPv4 header must be stripped")
	}
	if string(echo.Payload) != "inside" || echo.Path.Ident != 0x1111 {
		t.Fatalf("parsed = %+v payload=%q", echo.Path, echo.Payload)
	}

	// An IPv4 header with options: IHL = 6 -> 24 bytes.
	long := make([]byte, 24)
	long[0] = 0x46
	echo, ok = s.parse(append(long, icmp...))
	if !ok || string(echo.Payload) != "inside" {
		t.Fatalf("an IHL of 6 must be honoured (ok=%t payload=%q)", ok, echo.Payload)
	}

	// A truncated or nonsensical header is not recoverable.
	if _, ok := s.parse(ip[:10]); ok {
		t.Fatal("a truncated IPv4 header must be rejected")
	}
	brokenIHL := append([]byte(nil), raw...)
	brokenIHL[0] = 0x40 // IHL = 0
	if _, ok := s.parse(brokenIHL); ok {
		t.Fatal("an IHL below 20 must be rejected")
	}
}

func TestInterpretRawOpenErrorIsActionable(t *testing.T) {
	denied := interpretRawOpenError(fmt.Errorf("listen: %w", unix.EPERM), 4)
	if !errors.Is(denied, ErrNoCapNetRaw) {
		t.Fatalf("EPERM = %v, want ErrNoCapNetRaw", denied)
	}
	if msg := denied.Error(); !containsAll(msg, "CAP_NET_RAW", "setcap", "IPv4") {
		t.Fatalf("the refusal must name the capability, the fix and the family: %q", msg)
	}
	if eacces := interpretRawOpenError(unix.EACCES, 6); !errors.Is(eacces, ErrNoCapNetRaw) {
		t.Fatalf("EACCES = %v, want ErrNoCapNetRaw", eacces)
	}

	nosupport := interpretRawOpenError(fmt.Errorf("socket: %w", unix.EAFNOSUPPORT), 6)
	if !errors.Is(nosupport, ErrTransportUnsupported) {
		t.Fatalf("EAFNOSUPPORT = %v, want ErrTransportUnsupported", nosupport)
	}
	if !containsAll(nosupport.Error(), "no usable IPv6") {
		t.Fatalf("the message must name the family: %q", nosupport.Error())
	}

	other := interpretRawOpenError(errors.New("something else"), 4)
	if errors.Is(other, ErrNoCapNetRaw) || errors.Is(other, ErrTransportUnsupported) {
		t.Fatalf("an unrelated failure must not borrow a sentinel: %v", other)
	}
}

func TestInterpretSendErrorMapsTheProfileSentinels(t *testing.T) {
	if err := interpretSendError(nil); err != nil {
		t.Fatalf("nil = %v, want nil", err)
	}
	// EMSGSIZE is the one send failure that is MTU information rather than loss:
	// with IP_PMTUDISC_DO the kernel refuses a packet the path cannot carry.
	if err := interpretSendError(fmt.Errorf("write: %w", unix.EMSGSIZE)); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("EMSGSIZE = %v, want ErrRecordTooLarge", err)
	}
	for _, errno := range []error{unix.ENETUNREACH, unix.EHOSTUNREACH} {
		if err := interpretSendError(fmt.Errorf("write: %w", errno)); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("%v = %v, want ErrNoRoute", errno, err)
		}
	}
	if err := interpretSendError(errors.New("transient")); err == nil || errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("an unrelated error must pass through unchanged, got %v", err)
	}
}

func newRootICMPTransport(t *testing.T, bindV4, bindV6 bool) (*icmpTransport, *icmpCore) {
	t.Helper()
	resolved, err := (ICMPProfile{
		Family: "auto", MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ids, err := newPooledIDs("")
	if err != nil {
		t.Fatalf("id pool: %v", err)
	}
	core := newICMPCore(resolved, netip.AddrPort{}, ids, Nop{})
	plat, err := newPlatformICMPTransport(&icmpConfig{
		role: icmpRoleServer, family: familyAuto, core: core,
		bindV4: bindV4, bindV6: bindV6,
	})
	if err != nil {
		t.Fatalf("a privileged run must be able to open the raw carrier: %v", err)
	}
	tr := &icmpTransport{platform: plat, core: core}
	t.Cleanup(func() { _ = tr.Close() })
	return tr, core
}

func TestRawICMPLoopbackRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP sockets need CAP_NET_RAW; re-run as root to exercise the socket path")
	}
	tr, _ := newRootICMPTransport(t, true, false)

	if tr.LocalID() == "" || tr.RemoteID() == "" {
		t.Fatalf("labels = %q/%q", tr.LocalID(), tr.RemoteID())
	}
	if got := tr.RemoteID(); got != "any" {
		t.Fatalf("a server carrier must accept from anyone, remote label = %q", got)
	}
	if _, err := tr.Poke([]byte("probe"), netip.AddrPort{}); err == nil {
		t.Fatal("Poke without a destination must fail")
	}

	payload := []byte("icmp loopback round trip")
	if err := tr.WriteRecord(payload, netip.MustParseAddrPort("127.0.0.1:0")); err != nil {
		t.Fatalf("WriteRecord to loopback: %v", err)
	}

	// Best-effort observation: a host firewall may drop loopback ICMP, which is
	// not this test's business. Any packet that DOES arrive must, however, carry
	// our payload byte for byte — that is the property under test, and it covers
	// both the kernel's reply and our own request looping back.
	type observation []byte
	seen := make(chan observation, 1)
	go func() {
		buf := make([]byte, 1200)
		for i := 0; i < 4; i++ {
			echo, err := tr.platform.readEcho(buf)
			if err != nil {
				return
			}
			if echo.PathBudget > 0 || len(echo.Payload) == 0 {
				continue
			}
			out := make([]byte, len(echo.Payload))
			copy(out, echo.Payload)
			seen <- observation(out)
			return
		}
	}()
	select {
	case obs := <-seen:
		if string(obs) != string(payload) {
			t.Fatalf("loopback payload = %q, want %q", obs, payload)
		}
	case <-time.After(time.Second):
		// Nothing came back on loopback: tolerated (a firewall, or a container
		// with loopback ICMP disabled). The socket path itself already proved
		// itself by opening and sending.
	}
}

func TestRawICMPSendRejectionsAreExplicit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP sockets need CAP_NET_RAW; re-run as root to exercise the socket path")
	}
	tr, _ := newRootICMPTransport(t, true, false)

	if err := tr.WriteRecord([]byte("x"), netip.AddrPort{}); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("a record with no destination = %v, want ErrNoRoute", err)
	}

	// An IPv6 destination with only the IPv4 socket open cannot be reached; the
	// carrier must say so rather than silently dropping the record.
	err := tr.WriteRecord([]byte("x"), netip.MustParseAddrPort("[2001:db8::1]:0"))
	if err == nil {
		t.Fatal("an unreachable family must produce an error")
	}
}

func TestRawICMPCloseIsIdempotentAndUnblocksReads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP sockets need CAP_NET_RAW; re-run as root to exercise the socket path")
	}
	tr, _ := newRootICMPTransport(t, true, true)

	done := make(chan error, 1)
	go func() {
		_, _, err := tr.ReadRecord(make([]byte, 1200))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a pending ReadRecord must fail once the carrier closes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock ReadRecord")
	}
}

// TestRawICMPServerCarrierExposesTheFullCapabilitySurface is a compile-and-
// construct check on the real platform object: the session layer discovers
// these capabilities at runtime, so a platform file that forgot one would
// silently disable adaptation on Linux only.
func TestRawICMPServerCarrierExposesTheFullCapabilitySurface(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("raw ICMP sockets need CAP_NET_RAW; re-run as root to exercise the socket path")
	}
	tr, _ := newRootICMPTransport(t, true, true)

	var asTransport Transport = tr
	if maxRecordSizeOf(asTransport) <= 0 {
		t.Fatal("the raw carrier must publish a send budget")
	}
	if maxReceiveSizeOf(asTransport) <= 0 {
		t.Fatal("the raw carrier must publish a receive ceiling")
	}
	if pollerOf(asTransport) == nil || proberOf(asTransport) == nil {
		t.Fatal("the raw carrier must expose Poller and Prober")
	}
	if carrierConditionOf(asTransport) == nil {
		t.Fatal("the raw carrier must expose CarrierCondition")
	}
	if mtuFeedbackOf(asTransport) == nil || authenticatedFeedbackOf(asTransport) == nil {
		t.Fatal("the raw carrier must expose both feedback channels")
	}
}
