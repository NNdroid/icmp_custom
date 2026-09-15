package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/NNdroid/icmp_custom/tunnel"
)

// The CLI is the P6 deliverable, and its contract is small enough to test
// exhaustively: dispatch, the -c requirement, the generators, and — most
// importantly — the ACTIONABLE HINT on each of the three failure paths. A
// tunnel that refuses to start without saying why is the failure mode this
// whole layer exists to prevent.

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunDispatch(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCode int
		inStdout string
		inStderr string
	}{
		{"no args", nil, 2, "", "command is required"},
		{"unknown command", []string{"frobnicate"}, 2, "", "unknown command"},
		{"version", []string{"version"}, 0, "icmp_custom " + version, ""},
		{"version flag", []string{"--version"}, 0, "icmp_custom " + version, ""},
		{"help", []string{"help"}, 0, "Usage:", ""},
		{"help flag", []string{"-h"}, 0, "Usage:", ""},
		{"server without -c", []string{"server"}, 2, "", "-c <file> is required"},
		{"client without -c", []string{"client"}, 2, "", "-c <file> is required"},
		{"gen-config bad role", []string{"gen-config", "-role", "wat"}, 2, "", "-role must be"},
		{"gen-magic takes no args", []string{"gen-magic", "extra"}, 2, "", "no positional arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errb := runCLI(t, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d (stderr=%q)", code, tc.wantCode, errb)
			}
			if tc.inStdout != "" && !strings.Contains(out, tc.inStdout) {
				t.Fatalf("stdout %q does not contain %q", out, tc.inStdout)
			}
			if tc.inStderr != "" && !strings.Contains(errb, tc.inStderr) {
				t.Fatalf("stderr %q does not contain %q", errb, tc.inStderr)
			}
		})
	}
}

func TestRunGenMagic(t *testing.T) {
	seen := make(map[uint32]int)
	for i := 0; i < 16; i++ {
		code, out, errb := runCLI(t, "gen-magic")
		if code != 0 {
			t.Fatalf("gen-magic exit = %d, stderr=%q", code, errb)
		}
		line := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
		if !strings.HasPrefix(line, "0x") {
			t.Fatalf("gen-magic first line = %q, want a 0x-prefixed value", line)
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(line, "0x"), 16, 32)
		if err != nil {
			t.Fatalf("gen-magic value %q does not parse as a 32-bit hex value: %v", line, err)
		}
		magic := uint32(v)
		if magic == tunnel.ZeroMagic {
			t.Fatal("gen-magic produced the reserved zero magic")
		}
		seen[magic]++
	}
	// 16 draws producing a single value would mean the entropy source is
	// broken or the generator is returning a constant.
	if len(seen) < 2 {
		t.Fatalf("gen-magic returned only %d distinct value(s) in 16 draws", len(seen))
	}
}

// newMagic is the property under test: the two documented rules, over many
// draws, so a regression to "just return a random uint32" is caught.
func TestNewMagicIsNonZeroAndNonPrintable(t *testing.T) {
	for i := 0; i < 256; i++ {
		m, err := newMagic()
		if err != nil {
			t.Fatalf("newMagic: %v", err)
		}
		if m == tunnel.ZeroMagic {
			t.Fatal("newMagic returned zero, the wire sentinel for 'skip the check'")
		}
		var b [4]byte
		b[0], b[1], b[2], b[3] = byte(m>>24), byte(m>>16), byte(m>>8), byte(m)
		if isPrintableWord(b) {
			t.Fatalf("newMagic returned %#08x, which is four printable ASCII bytes (a DPI fingerprint)", m)
		}
	}
}

func TestIsPrintableWord(t *testing.T) {
	for _, tc := range []struct {
		in   [4]byte
		want bool
	}{
		{[4]byte{'U', 'D', 'P', 'C'}, true},
		{[4]byte{'a', 'b', 'c', 'd'}, true},
		{[4]byte{0xA7, 0xC3, 0xE5, 0x19}, false}, // the project default
		{[4]byte{'a', 'b', 'c', 0x00}, false},    // NUL is not printable
		{[4]byte{'a', 'b', 'c', ' '}, true},      // space is 0x20
		{[4]byte{'a', 'b', 'c', 0x7f}, false},    // DEL is not printable
	} {
		if got := isPrintableWord(tc.in); got != tc.want {
			t.Fatalf("isPrintableWord(%q) = %t, want %t", tc.in, got, tc.want)
		}
	}
}

func TestRunGenKeysProducesParseableKeys(t *testing.T) {
	code, out, errb := runCLI(t, "gen-keys")
	if code != 0 {
		t.Fatalf("gen-keys exit = %d, stderr=%q", code, errb)
	}
	priv := extractQuoted(t, out, `"privkey":`)
	pub := extractQuoted(t, out, `"server_pub":`)

	if _, err := tunnel.ParseNoiseKey(priv); err != nil {
		t.Fatalf("the printed private key does not parse: %v", err)
	}
	pubKey, err := tunnel.ParseNoiseKey(pub)
	if err != nil {
		t.Fatalf("the printed public key does not parse: %v", err)
	}
	if _, err := hex.DecodeString(priv); err != nil {
		t.Fatalf("private key is not hex: %v", err)
	}
	if _, err := hex.DecodeString(pub); err != nil {
		t.Fatalf("public key is not hex: %v", err)
	}

	// The two halves must differ: printing one value twice would produce a
	// tunnel that never comes up, and would still "parse".
	privKey, err := tunnel.ParseNoiseKey(priv)
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	if privKey == pubKey {
		t.Fatal("gen-keys printed the same value for the private and public halves")
	}
}

// extractQuoted pulls the value that follows a prefix like `"privkey":` out of
// the generator's human-readable output.
func extractQuoted(t *testing.T, out, prefix string) string {
	t.Helper()
	idx := strings.Index(out, prefix)
	if idx < 0 {
		t.Fatalf("output does not contain %q:\n%s", prefix, out)
	}
	rest := out[idx+len(prefix):]
	start := strings.IndexByte(rest, '"')
	if start < 0 {
		t.Fatalf("no quoted value after %q", prefix)
	}
	rest = rest[start+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatalf("unterminated quoted value after %q", prefix)
	}
	return rest[:end]
}

// The firewall script must cover BOTH families and must carry the ICMPv6
// warning. A v4-only rule set produces a tunnel that works over IPv4 and
// silently fails over IPv6; and an operator who "hardens" ICMPv6 by dropping
// it breaks Neighbor Discovery for the whole host.
func TestRunGenICMPRules(t *testing.T) {
	code, out, errb := runCLI(t, "gen-icmp-rules")
	if code != 0 {
		t.Fatalf("gen-icmp-rules exit = %d, stderr=%q", code, errb)
	}
	for _, want := range []string{
		"iptables", "ip6tables",
		"echo-request", "echo-reply",
		"icmpv6-type",
		"NEVER",
		"Neighbor Discovery",
		"discard://*",
		"icmp_msgs_per_sec",
		"[ICMP] carrier throttled",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("gen-icmp-rules output does not mention %q", want)
		}
	}
	// The dangerous construct must appear only inside the warning, never as a
	// suggested rule. Check there is no un-commented DROP line.
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "-j DROP") {
			t.Fatalf("gen-icmp-rules emits a live DROP rule: %q", line)
		}
	}
}

func TestRunGenConfigEmitsParsableTemplates(t *testing.T) {
	for _, role := range []string{"server", "client"} {
		code, out, errb := runCLI(t, "gen-config", "-role", role)
		if code != 0 {
			t.Fatalf("gen-config -role %s exit = %d, stderr=%q", role, code, errb)
		}
		cfg, err := ParseConfig([]byte(out), role+"-stdout")
		if err != nil {
			t.Fatalf("gen-config -role %s is not parsable: %v", role, err)
		}
		switch role {
		case "server":
			if _, err := cfg.ServerConfig(); err != nil {
				t.Fatalf("server template does not project: %v", err)
			}
		case "client":
			if _, err := cfg.ClientConfig(); err != nil {
				t.Fatalf("client template does not project: %v", err)
			}
		}
	}
}

func TestRunRoleReportsAMissingConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	for _, role := range []string{"server", "client"} {
		code, _, errb := runCLI(t, role, "-c", missing)
		if code != 1 {
			t.Fatalf("%s exit = %d, want 1", role, code)
		}
		if !strings.Contains(errb, "nope.json") {
			t.Fatalf("%s stderr %q does not name the missing file", role, errb)
		}
	}
}

// The three failure paths the design requires to be distinguishable, at the
// CLI boundary. On non-Linux the carrier cannot exist; on Linux without the
// capability the socket is refused. Either way the operator must get a hint,
// and the hint must be one of the two specific ones — not a bare error.
func TestRunServerCarrierFailureCarriesAnActionableHint(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		t.Skip("running as root: the raw carrier would actually open sockets and block")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, []byte(minimalServerJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	code, _, errb := runCLI(t, "server", "-c", path)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%q)", code, errb)
	}
	if !strings.Contains(errb, "hint:") {
		t.Fatalf("stderr has no actionable hint:\n%s", errb)
	}
	switch runtime.GOOS {
	case "linux":
		if !strings.Contains(errb, "setcap") {
			t.Fatalf("linux without CAP_NET_RAW should suggest setcap:\n%s", errb)
		}
	default:
		if !strings.Contains(errb, "no ICMP carrier") {
			t.Fatalf("%s should report the missing platform carrier:\n%s", runtime.GOOS, errb)
		}
	}
}

func TestRunServerReportsAnInvalidConfigWithAConfigHint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	// A bad profile value: the failure is the config, not the platform.
	bad := `{"target":"tcp://127.0.0.1:22","passwords":["x"],"icmp":{"max_payload":99999}}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	code, _, errb := runCLI(t, "server", "-c", path)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%q)", code, errb)
	}
	if !strings.Contains(errb, "hint: fix the configuration") {
		t.Fatalf("a config error should carry the config hint:\n%s", errb)
	}
	if !strings.Contains(errb, "max_payload") {
		t.Fatalf("the error should name the offending field:\n%s", errb)
	}
}
