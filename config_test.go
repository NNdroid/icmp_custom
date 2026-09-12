package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NNdroid/icmp_custom/tunnel"
)

// The config surface has two load-bearing properties that are easy to break
// silently, so both are pinned here:
//
//  1. UNKNOWN KEYS ARE IGNORED. A config carried over from a UDP deployment
//     carries `port_range` / `origdst` / `sendsock_max` / `receive_sockets`.
//     Those mechanisms have no ICMP counterpart, and the project's constraint
//     is that they be neither read nor rejected. Enabling
//     DisallowUnknownFields would break this, and nothing else would notice.
//
//  2. PASSWORDS AGGREGATE. `passwords`, `password` and `psk` (string or array)
//     all feed one de-duplicated list, because a silently-dropped credential
//     is indistinguishable from a wrong PSK at the first handshake.

const minimalServerJSON = `{
  "target": "tcp://127.0.0.1:22",
  "passwords": ["secret"]
}`

const minimalClientJSON = `{
  "server": "203.0.113.7",
  "listen": "127.0.0.1:1080",
  "passwords": ["secret"]
}`

func TestParseConfigAppliesDocumentedDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(minimalServerJSON), "test")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	// The zero ICMPProfile must be the documented default profile, so an
	// omitted block is indistinguishable from an explicit default one.
	if err := cfg.ICMP.Validate(); err != nil {
		t.Fatalf("the implicit default profile must validate: %v", err)
	}

	if _, err := cfg.ServerConfig(); err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
}

func TestParseConfigAcceptsComments(t *testing.T) {
	// Comments outside strings, plus a URL that CONTAINS "//" — the case a
	// naive regexp-based stripper would corrupt, taking the target with it.
	raw := `{
  // a line comment
  "target": "tcp://127.0.0.1:22",   // trailing comment
  /* a block
     comment */
  "passwords": ["se//cret", "a/*b*/c"],
  "allowed_targets": ["discard://*"]
}`
	cfg, err := ParseConfig([]byte(raw), "test")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Target != "tcp://127.0.0.1:22" {
		t.Fatalf("Target = %q, want the URL intact", cfg.Target)
	}
	want := []string{"se//cret", "a/*b*/c"}
	if len(cfg.Passwords) != len(want) {
		t.Fatalf("Passwords = %q, want %q", cfg.Passwords, want)
	}
	for i := range want {
		if cfg.Passwords[i] != want[i] {
			t.Fatalf("Passwords[%d] = %q, want %q (comment stripping corrupted a string)", i, cfg.Passwords[i], want[i])
		}
	}
	if len(cfg.AllowedTargets) != 1 || cfg.AllowedTargets[0] != "discard://*" {
		t.Fatalf("AllowedTargets = %q, want [discard://*]", cfg.AllowedTargets)
	}
}

func TestStripJSONCommentsPreservesStringContents(t *testing.T) {
	type tc struct {
		name string
		in   string
		want string
	}
	cases := []tc{
		{"no comment", `{"a":"b"}`, `{"a":"b"}`},
		{"line comment", "{\"a\":1} // tail\n", "{\"a\":1} \n"},
		{"block comment", `{"a":/*x*/1}`, `{"a":1}`},
		{"url kept", `{"u":"tcp://h:1"}`, `{"u":"tcp://h:1"}`},
		{"escaped quote", `{"u":"a\"b//c"}`, `{"u":"a\"b//c"}`},
		{"trailing backslash", `{"u":"a\\"}`, `{"u":"a\\"}`},
		{"only comments", "// nothing\n/* at all */", "\n"},
	}
	for _, c := range cases {
		got := string(stripJSONComments([]byte(c.in)))
		if got != c.want {
			t.Fatalf("%s: stripJSONComments(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestParseConfigAggregatesPasswordAliases(t *testing.T) {
	raw := `{
  "target": "tcp://127.0.0.1:22",
  "passwords": ["alpha", "  ", "beta", "alpha"],
  "password": "gamma",
  "psk": ["delta", "beta"]
}`
	cfg, err := ParseConfig([]byte(raw), "test")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	want := []string{"alpha", "beta", "gamma", "delta"}
	if fmt.Sprint(cfg.Passwords) != fmt.Sprint(want) {
		t.Fatalf("Passwords = %q, want %q (order preserved, blanks dropped, de-duplicated)", cfg.Passwords, want)
	}
	// The alias inputs are consumed, not left behind to be double-counted.
	if cfg.Password != "" || len(cfg.PSK) != 0 {
		t.Fatalf("aliases were not cleared: password=%q psk=%q", cfg.Password, cfg.PSK)
	}
}

func TestParseConfigAcceptsScalarPSK(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"target":"tcp://h:1","psk":"solo"}`), "test")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Passwords) != 1 || cfg.Passwords[0] != "solo" {
		t.Fatalf("Passwords = %q, want [solo]", cfg.Passwords)
	}
}

func TestParseConfigRejectsMalformedPSKShape(t *testing.T) {
	_, err := ParseConfig([]byte(`{"target":"tcp://h:1","psk":123}`), "test")
	if err == nil {
		t.Fatal("a numeric psk was accepted")
	}
	if !strings.Contains(err.Error(), "psk") {
		t.Fatalf("error %q does not name the psk field", err)
	}
}

func TestParseConfigRejectsMalformedJSON(t *testing.T) {
	_, err := ParseConfig([]byte(`{"target":`), "test")
	if err == nil {
		t.Fatal("truncated JSON was accepted")
	}
	if !strings.Contains(err.Error(), "test") {
		t.Fatalf("error %q does not name the config source", err)
	}
}

// The constraint-5 property. These keys belong to another project; the config
// must swallow them without error and without reading them.
func TestParseConfigIgnoresForeignUDPKeys(t *testing.T) {
	raw := `{
  "target": "tcp://127.0.0.1:22",
  "passwords": ["secret"],
  // A config carried over from a UDP deployment may still name the transport;
  // there is exactly one carrier, so the key is ignored like any other.
  "transport": "udp",
  "port_range": "20000-20100",
  "origdst": true,
  "sendsock_max": 64,
  "receive_sockets": 8,
  "listen": "0.0.0.0:1234",
  "some_future_field": {"nested": [1, 2, 3]}
}`
	cfg, err := ParseConfig([]byte(raw), "test")
	if err != nil {
		t.Fatalf("ParseConfig rejected a config carrying foreign keys: %v", err)
	}
	if _, err := cfg.ServerConfig(); err != nil {
		t.Fatalf("ServerConfig after foreign keys: %v", err)
	}
}

func TestServerConfigRequiresTargetAndPasswords(t *testing.T) {
	t.Run("missing target", func(t *testing.T) {
		cfg := &Config{Passwords: []string{"secret"}}
		_, err := cfg.ServerConfig()
		if !errors.Is(err, tunnel.ErrConfigRequired) {
			t.Fatalf("error %v does not wrap ErrConfigRequired", err)
		}
		if !strings.Contains(err.Error(), "target") {
			t.Fatalf("error %q does not name 'target'", err)
		}
	})
	t.Run("missing passwords", func(t *testing.T) {
		cfg := &Config{Target: "tcp://127.0.0.1:22"}
		_, err := cfg.ServerConfig()
		if !errors.Is(err, tunnel.ErrConfigRequired) {
			t.Fatalf("error %v does not wrap ErrConfigRequired", err)
		}
		if !strings.Contains(err.Error(), "passwords") {
			t.Fatalf("error %q does not name 'passwords'", err)
		}
	})
	t.Run("blank-only passwords", func(t *testing.T) {
		cfg := &Config{Target: "tcp://127.0.0.1:22", Passwords: []string{"  ", "\t"}}
		if _, err := cfg.ServerConfig(); !errors.Is(err, tunnel.ErrConfigRequired) {
			t.Fatalf("blank passwords produced %v, want ErrConfigRequired", err)
		}
	})
}

func TestClientConfigRequiresServerListenAndPasswords(t *testing.T) {
	base := func() *Config {
		return &Config{Server: "203.0.113.7", Listen: "127.0.0.1:1080", Passwords: []string{"secret"}}
	}
	t.Run("baseline is valid", func(t *testing.T) {
		if _, err := base().ClientConfig(); err != nil {
			t.Fatalf("baseline rejected: %v", err)
		}
	})
	for _, tc := range []struct {
		name string
		drop func(*Config)
		word string
	}{
		{"missing server", func(c *Config) { c.Server = "" }, "server"},
		{"missing listen", func(c *Config) { c.Listen = "" }, "listen"},
		{"missing passwords", func(c *Config) { c.Passwords = nil }, "passwords"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.drop(c)
			_, err := c.ClientConfig()
			if !errors.Is(err, tunnel.ErrConfigRequired) {
				t.Fatalf("error %v does not wrap ErrConfigRequired", err)
			}
			if !strings.Contains(err.Error(), tc.word) {
				t.Fatalf("error %q does not name %q", err, tc.word)
			}
		})
	}
}

func TestClientConfigParsesServerPub(t *testing.T) {
	kp, err := tunnel.GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("GenerateNoiseKeyPair: %v", err)
	}
	pubHex, pubB64 := tunnel.FormatNoiseKey(kp.PublicKey)

	for name, encoded := range map[string]string{"hex": pubHex, "base64": pubB64} {
		cc, err := (&Config{
			Server: "203.0.113.7", Listen: "127.0.0.1:1080",
			Passwords: []string{"secret"}, ServerPub: encoded,
		}).ClientConfig()
		if err != nil {
			t.Fatalf("%s: ClientConfig: %v", name, err)
		}
		if cc.ServerPub != kp.PublicKey {
			t.Fatalf("%s: ServerPub did not round-trip", name)
		}
	}

	if _, err := (&Config{
		Server: "203.0.113.7", Listen: "127.0.0.1:1080",
		Passwords: []string{"secret"}, ServerPub: "not-a-key",
	}).ClientConfig(); err == nil {
		t.Fatal("a malformed server_pub was accepted")
	} else if !errors.Is(err, tunnel.ErrBadKey) {
		t.Fatalf("error %v does not wrap ErrBadKey", err)
	}
}

func TestClientConfigMapsHandshakeBackoffAndProfile(t *testing.T) {
	cc, err := (&Config{
		Server: "203.0.113.7", Listen: "127.0.0.1:1080",
		Passwords:          []string{"secret"},
		HandshakeAttempts:  3,
		HandshakeBackoffMS: 250,
		ICMP:               tunnel.ICMPProfile{PollsInFlight: 7, PaceMS: 40, IdlePollMS: 500, KeepAliveMS: 4000},
	}).ClientConfig()
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if cc.HandshakeAttempts != 3 {
		t.Fatalf("HandshakeAttempts = %d, want 3", cc.HandshakeAttempts)
	}
	if cc.HandshakeBackoff != 250*time.Millisecond {
		t.Fatalf("HandshakeBackoff = %v, want 250ms (ms must not be read as ns)", cc.HandshakeBackoff)
	}
	if cc.ICMP.PollsInFlight != 7 || cc.ICMP.PaceMS != 40 {
		t.Fatalf("profile did not survive projection: %+v", cc.ICMP)
	}
}

// The templates are the onboarding surface. If a template stops parsing, or
// stops projecting, the first thing a new operator does fails — so both are
// checked for both roles.
func TestTemplatesParseAndProject(t *testing.T) {
	for _, role := range []string{"server", "client"} {
		raw := templateFor(role)
		cfg, err := ParseConfig([]byte(raw), role+"-template")
		if err != nil {
			t.Fatalf("%s template does not parse: %v", role, err)
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

func TestTemplateForUnknownRoleFallsBackToServer(t *testing.T) {
	if templateFor("nonsense") != templateFor("server") {
		t.Fatal("an unknown role must fall back to the server template")
	}
}

func TestWriteTemplateMatchesTemplateFor(t *testing.T) {
	var b strings.Builder
	if err := WriteTemplate(&b, "client"); err != nil {
		t.Fatalf("WriteTemplate: %v", err)
	}
	if b.String() != templateFor("client") {
		t.Fatal("WriteTemplate and templateFor disagree")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig("does-not-exist-" + runtime.GOOS + ".json")
	if err == nil {
		t.Fatal("LoadConfig accepted a missing file")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Fatalf("error %q does not name the path", err)
	}
}
