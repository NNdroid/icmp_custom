package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The pure ICMP Echo plumbing in icmp_echo.go.
//
// These tests carry NO build tag on purpose: the wire format is defined once
// in icmp_echo.go and shared by every platform carrier (raw Linux, Android
// ping sockets), so its tests must run on every host too — including a plain
// `go test ./...` on a Windows or macOS laptop, not just Linux CI.
// ---------------------------------------------------------------------------

func TestParseICMPMessageV4EchoRequestAndReply(t *testing.T) {
	payload := []byte("record bytes")
	msg := buildEchoMessage(8, 0x1234, 0x0102, payload, true)

	echo, ok := parseICMPMessage(msg, 4)
	if !ok {
		t.Fatal("an IPv4 echo request must parse")
	}
	if !echo.IsRequest {
		t.Fatal("type 8 is an Echo Request")
	}
	if echo.Path.Ident != 0x1234 || echo.Path.Seq != 0x0102 {
		t.Fatalf("path = %+v, want ident 0x1234 seq 0x0102", echo.Path)
	}
	if string(echo.Payload) != string(payload) {
		t.Fatalf("payload = %q, want %q", echo.Payload, payload)
	}
	if echo.PathBudget != 0 {
		t.Fatalf("an echo must not carry a path budget (%d)", echo.PathBudget)
	}

	reply, ok := parseICMPMessage(buildEchoMessage(0, 0x1234, 0x0102, payload, true), 4)
	if !ok || reply.IsRequest {
		t.Fatalf("type 0 must parse as an Echo Reply (ok=%t request=%t)", ok, reply.IsRequest)
	}
}

func TestParseICMPMessageV4FragmentationNeeded(t *testing.T) {
	// type 3 code 4, next-hop MTU in the 16 bits at offset 6 (RFC 1191).
	msg := make([]byte, 8)
	msg[0], msg[1] = 3, 4
	binary.BigEndian.PutUint16(msg[6:8], 1400)

	echo, ok := parseICMPMessage(msg, 4)
	if !ok {
		t.Fatal("frag-needed must parse")
	}
	// The platform converts the next-hop MTU into a RECORD budget by removing
	// the IPv4 and ICMP headers.
	if want := 1400 - ipv4HeaderOverhead; echo.PathBudget != want {
		t.Fatalf("path budget = %d, want %d", echo.PathBudget, want)
	}
	if len(echo.Payload) != 0 {
		t.Fatalf("a frag-needed message carries no record, got %d bytes", len(echo.Payload))
	}

	// Some implementations zero offset 6 and use offset 4 instead.
	alt := make([]byte, 8)
	alt[0], alt[1] = 3, 4
	binary.BigEndian.PutUint16(alt[4:6], 1300)
	echo, ok = parseICMPMessage(alt, 4)
	if !ok || echo.PathBudget != 1300-ipv4HeaderOverhead {
		t.Fatalf("the offset-4 fallback was not honoured: ok=%t budget=%d", ok, echo.PathBudget)
	}
}

func TestParseICMPMessageV4RejectsOtherUnreachables(t *testing.T) {
	// Only "fragmentation needed" carries MTU information; the rest are not
	// ours and must be dropped rather than guessed at.
	for _, code := range []byte{0, 1, 3, 5, 9, 13} {
		msg := make([]byte, 8)
		msg[0], msg[1] = 3, code
		binary.BigEndian.PutUint16(msg[6:8], 1400)
		if _, ok := parseICMPMessage(msg, 4); ok {
			t.Fatalf("type 3 code %d must be ignored", code)
		}
	}
	// An implausibly small "MTU" is not a usable path report.
	msg := make([]byte, 8)
	msg[0], msg[1] = 3, 4
	binary.BigEndian.PutUint16(msg[6:8], 40)
	if _, ok := parseICMPMessage(msg, 4); ok {
		t.Fatal("a next-hop MTU below 68 must be rejected")
	}
}

func TestParseICMPMessageV6EchoAndPacketTooBig(t *testing.T) {
	payload := []byte("v6 record")
	msg := buildEchoMessage(128, 7, 9, payload, false)
	echo, ok := parseICMPMessage(msg, 6)
	if !ok || !echo.IsRequest {
		t.Fatalf("ICMPv6 type 128 must parse as an Echo Request (ok=%t)", ok)
	}
	if string(echo.Payload) != string(payload) || echo.Path.Ident != 7 || echo.Path.Seq != 9 {
		t.Fatalf("v6 echo = %+v payload=%q", echo.Path, echo.Payload)
	}

	if reply, ok := parseICMPMessage(buildEchoMessage(129, 7, 9, payload, false), 6); !ok || reply.IsRequest {
		t.Fatalf("ICMPv6 type 129 must parse as an Echo Reply (ok=%t)", ok)
	}

	// Packet Too Big: a 32-bit MTU at offset 4.
	ptb := make([]byte, 8)
	ptb[0] = 2
	binary.BigEndian.PutUint32(ptb[4:8], 1280)
	echo, ok = parseICMPMessage(ptb, 6)
	if !ok {
		t.Fatal("Packet Too Big must parse")
	}
	if want := 1280 - ipv6HeaderOverhead; echo.PathBudget != want {
		t.Fatalf("path budget = %d, want %d", echo.PathBudget, want)
	}

	bad := make([]byte, 8)
	bad[0] = 2
	binary.BigEndian.PutUint32(bad[4:8], 1000) // below the IPv6 minimum
	if _, ok := parseICMPMessage(bad, 6); ok {
		t.Fatal("a Packet Too Big MTU below 1280 must be rejected")
	}
}

func TestParseICMPMessageRejectsJunk(t *testing.T) {
	cases := []struct {
		name   string
		msg    []byte
		family int
	}{
		{"too short", make([]byte, 7), 4},
		{"unknown v4 type", []byte{99, 0, 0, 0, 0, 0, 0, 0}, 4},
		{"unknown v6 type", []byte{99, 0, 0, 0, 0, 0, 0, 0}, 6},
		{"v4 echo delivered as v6", append([]byte{8, 0, 0, 0, 0, 1, 0, 2}, "x"...), 6},
		{"v6 echo delivered as v4", append([]byte{128, 0, 0, 0, 0, 1, 0, 2}, "x"...), 4},
		{"empty", nil, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseICMPMessage(tc.msg, tc.family); ok {
				t.Fatalf("%s must be ignored", tc.name)
			}
		})
	}
}

func TestBuildEchoMessageChecksumOnlyForIPv4(t *testing.T) {
	msg := buildEchoMessage(8, 0xABCD, 0x0001, []byte("odd"), true)

	// Re-summing a message that already contains its own one's-complement
	// checksum yields zero: that is what "the checksum is valid" means.
	if got := icmpv4Checksum(msg); got != 0 {
		t.Fatalf("icmpv4Checksum over a finalized message = %#x, want 0", got)
	}

	// Both header fields round-trip.
	if binary.BigEndian.Uint16(msg[4:6]) != 0xABCD || binary.BigEndian.Uint16(msg[6:8]) != 1 {
		t.Fatalf("ident/seq = %#x/%#x", binary.BigEndian.Uint16(msg[4:6]), binary.BigEndian.Uint16(msg[6:8]))
	}
	if string(msg[8:]) != "odd" {
		t.Fatalf("payload = %q", msg[8:])
	}
	if len(msg) != 8+3 {
		t.Fatalf("message length = %d, want 11", len(msg))
	}

	// IPv6 must leave the checksum field alone: RFC 3542 §3.1 has the kernel
	// compute and insert it, and IPV6_CHECKSUM is rejected EINVAL.
	v6 := buildEchoMessage(128, 1, 2, []byte("payload"), false)
	if binary.BigEndian.Uint16(v6[2:4]) != 0 {
		t.Fatalf("the ICMPv6 checksum field = %#x, want it left zero for the kernel",
			binary.BigEndian.Uint16(v6[2:4]))
	}

	// A ping socket lets the kernel checksum BOTH families, so withChecksum
	// false on IPv4 must likewise leave the field zero.
	v4 := buildEchoMessage(8, 1, 2, []byte("payload"), false)
	if binary.BigEndian.Uint16(v4[2:4]) != 0 {
		t.Fatalf("a checksum-free IPv4 message must leave the field zero")
	}
}

func TestICMPv4ChecksumBalancesAnEvenLengthMessage(t *testing.T) {
	// A message with an even length exercises the plain 16-bit accumulation.
	msg := buildEchoMessage(8, 0, 0, []byte("even"), true)
	if got := icmpv4Checksum(msg); got != 0 {
		t.Fatalf("checksum verification = %#x, want 0", got)
	}
}

func TestICMPv4ChecksumOfAnEmptyMessage(t *testing.T) {
	// The degenerate case must not panic and must yield the "no data" sum.
	if got := icmpv4Checksum(nil); got != 0xffff {
		t.Fatalf("checksum of nothing = %#x, want 0xffff", got)
	}
}

func TestNetipAddrOfUnmapsIPv4InIPv6(t *testing.T) {
	got := netipAddrOf(&net.IPAddr{IP: net.ParseIP("::ffff:192.0.2.7")})
	if !got.Is4() || got.String() != "192.0.2.7" {
		t.Fatalf("v4-mapped address = %v, want the unmapped 192.0.2.7", got)
	}

	got = netipAddrOf(&net.IPAddr{IP: net.ParseIP("2001:db8::1")})
	if !got.Is6() || got.Is4In6() {
		t.Fatalf("native IPv6 address = %v", got)
	}

	// The ping-socket carrier reads peers through a UDPConn, whose ReadFrom
	// reports *net.UDPAddr — the "port" is the ICMP ident and is ignored here.
	got = netipAddrOf(&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4242})
	if !got.Is4() || got.String() != "203.0.113.7" {
		t.Fatalf("UDPAddr peer = %v, want 203.0.113.7", got)
	}

	if a := netipAddrOf(&net.TCPAddr{}); a.IsValid() {
		t.Fatalf("a non-IPAddr source must yield the zero Addr, got %v", a)
	}
	if a := netipAddrOf(&net.IPAddr{}); a.IsValid() {
		t.Fatalf("a nil IP must yield the zero Addr, got %v", a)
	}
	if a := netipAddrOf(&net.UDPAddr{Port: 80}); a.IsValid() {
		t.Fatalf("a UDPAddr with a nil IP must yield the zero Addr, got %v", a)
	}
}

func TestCombineOpenErrorsKeepsEverySentinel(t *testing.T) {
	if err := combineOpenErrors(nil); !errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("no errors at all = %v, want ErrTransportUnsupported", err)
	}
	single := fmt.Errorf("ipv4: %w", ErrNoCapNetRaw)
	if got := combineOpenErrors([]error{single}); !errors.Is(got, ErrNoCapNetRaw) {
		t.Fatalf("a single failure must pass through: %v", got)
	}
	// With family "auto" an operator needs to see both halves' reasons.
	joined := combineOpenErrors([]error{
		fmt.Errorf("ipv4: %w", ErrNoCapNetRaw),
		fmt.Errorf("ipv6: %w", ErrTransportUnsupported),
	})
	if !errors.Is(joined, ErrNoCapNetRaw) || !errors.Is(joined, ErrTransportUnsupported) {
		t.Fatalf("a joined failure must keep every sentinel: %v", joined)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
