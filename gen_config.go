package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/NNdroid/icmp_custom/tunnel"
)

// The `gen-*` helpers.
//
// Each one exists to remove a specific opportunity for a hand-built mistake
// that would be expensive to debug later:
//
//   - gen-keys:  a 32-byte Curve25519 key, correctly clamped, in both textual
//                forms the config accepts.
//   - gen-magic: a record magic that is non-zero (zero means "skip the check")
//                and that is not a printable ASCII word, because the magic
//                travels in the clear and a string-shaped magic is a DPI
//                fingerprint. This is the whole reason the project does not
//                reuse "UDPC".
//   - gen-rules: firewall rules that allow echo request/reply in BOTH
//                directions on BOTH families — and that say, in the output,
//                why ICMPv6 must never be blocked wholesale (NDP depends on
//                it). A rule set that "secures" ICMPv6 by dropping it breaks
//                IPv6 connectivity for the whole host.

// genKeys writes a fresh Noise static key pair.
func genKeys(w io.Writer) error {
	kp, err := tunnel.GenerateNoiseKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}
	privHex, privB64 := tunnel.FormatNoiseKey(kp.PrivateKey)
	pubHex, pubB64 := tunnel.FormatNoiseKey(kp.PublicKey)

	fmt.Fprintln(w, "# Noise_NK static key pair (Curve25519).")
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# Keep the private key on the SERVER only. Put the public key in the")
	fmt.Fprintln(w, "# CLIENT's config as \"server_pub\". Without this pair the tunnel still")
	fmt.Fprintln(w, "# works (PSK-only, confidential) but has no forward secrecy.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# server.json")
	fmt.Fprintf(w, "  \"privkey\": %q\n", privHex)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# client.json")
	fmt.Fprintf(w, "  \"server_pub\": %q\n", pubHex)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Alternate encodings (any 32-byte hex or base64 form is accepted):")
	fmt.Fprintf(w, "#   private key (base64): %s\n", privB64)
	fmt.Fprintf(w, "#   public  key (base64): %s\n", pubB64)
	return nil
}

// genMagic writes a fresh record magic.
func genMagic(w io.Writer) error {
	magic, err := newMagic()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "0x%08x\n", magic)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# Paste into BOTH config files (they must match):")
	fmt.Fprintf(w, "#   \"magic\": %d\n", magic)
	return nil
}

// newMagic draws a magic that satisfies the two documented rules: it is never
// zero (zero is the wire sentinel for "skip the magic check"), and it is not
// four printable ASCII bytes (a string-shaped magic is a fingerprint that a
// plain DPI rule can match).
func newMagic() (uint32, error) {
	var b [4]byte
	for attempt := 0; attempt < 64; attempt++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("generate magic: %w", err)
		}
		v := binary.BigEndian.Uint32(b[:])
		if v == tunnel.ZeroMagic || isPrintableWord(b) {
			continue
		}
		return v, nil
	}
	// Unreachable in practice: ~2 * 10^-6 of the 32-bit space is rejected, so
	// 64 consecutive rejections would mean the entropy source is broken.
	return 0, fmt.Errorf("generate magic: no acceptable value after 64 draws (entropy source?)")
}

// isPrintableWord reports whether all four bytes are printable ASCII. Such a
// value can be matched by a naive middlebox string rule, which is exactly the
// fingerprinting this project avoids.
func isPrintableWord(b [4]byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// genICMPRules writes an allow-list for the ICMP echo path, for both families.
func genICMPRules(w io.Writer) error {
	fmt.Fprint(w, icmpRulesScript)
	return nil
}

// icmpRulesScript is emitted verbatim by gen-icmp-rules. It is a SCRIPT for a
// human to read and run, not something this program executes: editing a
// firewall is an operator decision.
const icmpRulesScript = `#!/bin/sh
# ICMP echo rules for icmp_custom.
#
# The tunnel needs echo request AND echo reply to pass in BOTH directions:
# the client polls with a request and the server answers with a reply, and the
# server's reverse probe is the same in the other direction. Allowing only one
# direction produces a tunnel that comes up and then carries nothing.
#
# Run as root, on BOTH ends (or on the router/NAT in front of them).

set -e

# ---- IPv4 ----
# Allow echo request/reply on the INPUT and OUTPUT chains.
iptables -C INPUT  -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || \
    iptables -A INPUT  -p icmp --icmp-type echo-request -j ACCEPT
iptables -C INPUT  -p icmp --icmp-type echo-reply   -j ACCEPT 2>/dev/null || \
    iptables -A INPUT  -p icmp --icmp-type echo-reply   -j ACCEPT
iptables -C OUTPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || \
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -C OUTPUT -p icmp --icmp-type echo-reply   -j ACCEPT 2>/dev/null || \
    iptables -A OUTPUT -p icmp --icmp-type echo-reply   -j ACCEPT

# ---- IPv6 ----
# !! NEVER use ` + "`" + `-p ipv6-icmp -j DROP` + "`" + ` or drop ICMPv6 wholesale. !!
# IPv6 does not work without ICMPv6: Neighbor Discovery (types 133-137),
# Router Advertisement/Solicitation (134/133) and Packet Too Big (2) are all
# ICMPv6, and blocking them breaks address resolution and PMTU for the ENTIRE
# host, not just this tunnel. Allow only the echo types, exactly as above.
ip6tables -C INPUT  -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT 2>/dev/null || \
    ip6tables -A INPUT  -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
ip6tables -C INPUT  -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT 2>/dev/null || \
    ip6tables -A INPUT  -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
ip6tables -C OUTPUT -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT 2>/dev/null || \
    ip6tables -A OUTPUT -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
ip6tables -C OUTPUT -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT 2>/dev/null || \
    ip6tables -A OUTPUT -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT

# ---- Host rate limit (optional, Linux) ----
# The kernel charges ICMP against a GLOBAL per-host allowance, shared with any
# ` + "`" + `ping` + "`" + ` you run. A too-small allowance looks exactly like a lossy path, and the
# tunnel then retransmits into the limiter, making things worse. If the carrier
# reports THROTTLED, raise these rather than lowering pace_ms alone:
#
#   sysctl -w net.ipv4.icmp_msgs_per_sec=1000
#   sysctl -w net.ipv4.icmp_msgs_burst=50
#
# Verify what the carrier classified (the three log signatures are distinct):
#   [ICMP] path healthy peer=...         - replies are flowing
#   [ICMP] carrier throttled ...         - replies arrive but too few / slow
#   [ICMP] carrier blocked ... replies=0 - nothing comes back

# ---- For the handshake-time MTU probe (icmp.mtu_mode = "probe") ----
# The server must be allowed to forward to the built-in sink:
#   "allowed_targets": ["discard://*"]
# Nothing else is needed; the sink never leaves the process.
`

// templateFor returns the documented starter configuration for a role. The
// text is deliberately commented: it is the operator's onboarding surface and
// the place the "no UDP profile" boundary is stated where it matters.
func templateFor(role string) string {
	if role == "client" {
		return clientTemplate
	}
	return serverTemplate
}

const serverTemplate = `{
  "log_level": "info",

  // The default forwarding endpoint for clients that request none.
  // Use "discard://" (and allow it below) to enable the MTU probe.
  "target": "tcp://127.0.0.1:22",

  // Accepted PSKs. At least one is mandatory; there is no open mode.
  // ` + "`psk`" + ` and ` + "`password`" + ` are accepted as aliases. Use a
  // HIGH-ENTROPY secret (e.g. ` + "`openssl rand -base64 24`" + `); short or
  // human-guessable values are brute-forceable online, and there is no
  // second factor.
  "passwords": ["CHANGE-ME"],

  // Optional: enables Noise_NK forward secrecy. Generate with ` + "`gen-keys`" + `.
  "privkey": "",

  // Client-requested endpoints that will be granted. Patterns take '*' and
  // '?'. An empty list means only "target" above is reachable.
  // Add "discard://*" to allow the client's MTU probe.
  "allowed_targets": [],

  // Record magic. Leave 0 for the default, or generate one with ` + "`gen-magic`" + `
  // and use the SAME value on both ends. Not a security boundary: it is a
  // cheap prefilter, chosen to avoid a string fingerprint.
  "magic": 0,

  "send_window": 256,

  "icmp": {
    "max_payload": 1200,     // start and hard ceiling of the MTU search
    "mtu_mode": "probe",     // probe | auto (in-band only) | fixed
    "mtu_min": 548,          // never step below (IPv4 reassembly floor)
    "mtu_step": 100,         // upward step, halved near the ceiling
    "pace_ms": 20,           // spaces outbound packets; both ends need it
    "id_range": "",          // e.g. "1000-1999"; empty = a fresh id per packet
    "probe": true,           // server-initiated reverse probe (best-effort)
    "block_timeout": "60s"   // how long a fully blocked carrier is tolerated
  }
}
`

const clientTemplate = `{
  "log_level": "info",

  // The peer to tunnel to. ICMP binds no port, so a bare host is natural;
  // "host:port" is accepted and the port ignored.
  "server": "203.0.113.7",

  // The endpoint requested from the server. Leave empty for its default.
  "target": "tcp://127.0.0.1:22",

  // Must match the server's PSK. Use a HIGH-ENTROPY secret; short or
  // human-guessable values are brute-forceable online.
  "passwords": ["CHANGE-ME"],

  // Optional: the server's Noise public key (from ` + "`gen-keys`" + `). Empty =
  // PSK-only mode: still confidential, without forward secrecy.
  "server_pub": "",

  // Local address applications connect to.
  "listen": "127.0.0.1:1080",

  "magic": 0,
  "send_window": 256,

  // The ICMP path often has a higher RTT and may be rate-limited.
  "handshake_attempts": 8,
  "handshake_backoff_ms": 400,

  "icmp": {
    "max_payload": 1200,
    "mtu_mode": "probe",
    "mtu_min": 548,
    "mtu_step": 100,
    "pace_ms": 20,
    "id_range": "",
    "probe": true,
    "polls_in_flight": 4,    // the downlink throughput ceiling (~ window / RTT)
    "idle_poll_ms": 1000,
    "keepalive_ms": 15000,
    "block_timeout": "60s"
  }
}
`
