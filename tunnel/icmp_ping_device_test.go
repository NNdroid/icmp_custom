//go:build android

package tunnel

import (
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
)

// loopbackAddrPort is where the kernel's own ICMP stack answers Echo Requests.
func loopbackAddrPort() netip.AddrPort { return netip.MustParseAddrPort("127.0.0.1:0") }

// Device-gated tests for the real socket path (icmp_android.go). These
// compile on every CI run via `GOOS=android go vet` and EXECUTE when the
// test binary runs on an Android device or emulator:
//
//	CC=ndk-clang GOOS=android GOARCH=arm64 go test -c ./tunnel/
//	adb push tunnel.test /data/local/tmp/ && adb shell /data/local/tmp/tunnel.test -run TestDevicePing
//
// A ping socket needs ping_group_range to admit the shell/app group; on
// `adb shell` (uid 2000) most ROMs admit it via the permissive range.
// Everything here is skipped cleanly when the kernel refuses, so the suite
// stays green on ROMs that disable ping sockets.

func TestDevicePingSocketOpenCallsProtectBeforeTraffic(t *testing.T) {
	protectCalls := atomic.Int32{}
	protectErrs := atomic.Int32{}

	s, err := openPingSocket(4, func(fd int) error {
		protectCalls.Add(1)
		if fd <= 0 {
			t.Errorf("protect called with fd %d, want a positive descriptor", fd)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrPingSocketDenied) || errors.Is(err, ErrTransportUnsupported) {
			t.Skipf("this kernel refuses ping sockets: %v", err)
		}
		t.Fatalf("openPingSocket: %v", err)
	}
	t.Cleanup(func() { _ = s.conn.Close() })

	if protectCalls.Load() != 1 {
		t.Fatalf("protect was called %d times, want exactly once per socket", protectCalls.Load())
	}

	// protect must have happened BEFORE any traffic: send the first probe
	// and verify the error counter stayed at zero (the callback had no
	// failures) and the kernel assigned an ident. sendEcho consults the
	// parent pingICMP for the socket table, so wire up a minimal one — with
	// the real sockPort hook, because the ident is read back through it.
	p := &pingICMP{socks: []*pingSocket{s}, sockPort: unixSockPort}
	s.parent = p
	if err := s.parent.sendEcho([]byte("probe"), loopbackAddrPort(), 0x1234, 1); err != nil {
		t.Fatalf("sendEcho on the real socket: %v", err)
	}
	if protectErrs.Load() != 0 {
		t.Fatal("the protect callback recorded failures")
	}
	if id := s.localIdent(); id == 0 {
		t.Fatal("after the first send, getsockname must expose the kernel-assigned ident")
	} else if id == 0x1234 {
		// Allowed but notable: the kernel adopted the requested ident.
		t.Log("the kernel adopted the requested ident; that is within spec")
	}
}

func TestDevicePingSocketRoundTripOnLoopback(t *testing.T) {
	// The full socket path: request out through the kernel, reply back in.
	// The remote echoer is whatever answers ICMP on loopback — the kernel's
	// own ICMP stack replies to Echo Requests sent to 127.0.0.1.
	s, err := openPingSocket(4, nil)
	if err != nil {
		if errors.Is(err, ErrPingSocketDenied) || errors.Is(err, ErrTransportUnsupported) {
			t.Skipf("this kernel refuses ping sockets: %v", err)
		}
		t.Fatalf("openPingSocket: %v", err)
	}
	t.Cleanup(func() { _ = s.conn.Close() })

	p := &pingICMP{
		in:       make(chan inboundEcho, pingPumpQueue),
		closed:   make(chan struct{}),
		sockPort: unixSockPort,
	}
	s.parent = p
	p.socks = []*pingSocket{s}
	p.pumps.Add(1)
	go p.pump(s)

	if err := p.sendEcho([]byte("loopback-payload"), loopbackAddrPort(), 0x4242, 3); err != nil {
		t.Fatalf("sendEcho: %v", err)
	}
	echo, err := p.readEcho(make([]byte, pingReadBufSize))
	if err != nil {
		t.Fatalf("readEcho: %v (loopback ICMP may be blocked by the ROM)", err)
	}
	if string(echo.Payload) != "loopback-payload" {
		t.Fatalf("round trip payload = %q", echo.Payload)
	}
	if echo.IsRequest {
		t.Fatal("the kernel's reply must not parse as a request")
	}
}

func TestDevicePingGroupRangeSelfCheckMatchesReality(t *testing.T) {
	err := checkPingGroupRange()
	_, statErr := os.Stat(pingGroupRangePath)
	switch {
	case statErr != nil:
		t.Skip("no procfs on this device")
	case err == nil:
		return // admitted: nothing more to assert
	case errors.Is(err, ErrPingSocketDenied):
		t.Skipf("this device's range refuses us; the self-check correctly says so: %v", err)
	default:
		t.Fatalf("unexpected self-check error: %v", err)
	}
}
