package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/NNdroid/icmp_custom/tunnel"
)

// The on-disk configuration.
//
// One file describes one role. There is exactly one configuration source — the
// `-c <file>` flag — and no environment variables, no auto-scanned
// `config.json`, and no default-path fallback: a tunnel whose parameters are
// silently guessed is worse than one that refuses to start.
//
// Two properties are load-bearing and easy to get wrong:
//
//  1. UNKNOWN KEYS ARE IGNORED, never rejected. A config carried over from a
//     UDP deployment still carries `port_range` / `origdst` / `sendsock_max` /
//     `receive_sockets` / `listen`. Those mechanisms have no ICMP counterpart
//     (see DESIGN_ICMP.md §6), and the project's constraint is that they be
//     neither read nor treated as errors. encoding/json does exactly that, so
//     `DisallowUnknownFields` must never be enabled.
//
//  2. The flat fields below are the whole accepted surface. The role
//     projections (ServerConfig / ClientConfig) are built explicitly rather
//     than by decoding the same object twice, because a double decode would
//     let a top-level `idle_poll_ms` land in a `time.Duration` field as
//     nanoseconds. Explicit projection makes the JSON vocabulary and the Go
//     types agree by construction.
type Config struct {
	// Transport names the carrier: "icmp" (default, and the only one). An
	// empty value selects it.
	Transport string `json:"transport"`
	// LogLevel is debug|info|warn|error.
	LogLevel string `json:"log_level"`
	// ICMP is the ICMP carrier profile. Its zero value is the documented
	// default profile, so an omitted block means "defaults".
	ICMP tunnel.ICMPProfile `json:"icmp"`

	// ---- server role ----

	// Target is the default forwarding endpoint ("tcp://host:port"), and — in
	// client mode — the endpoint requested in the handshake.
	Target string `json:"target"`
	// AllowedTargets gates client-REQUESTED endpoints. To enable the
	// handshake-time MTU probe (mtu_mode "probe") allow "discard://*".
	AllowedTargets []string `json:"allowed_targets"`
	// PrivKey enables Noise_NK on the server (32-byte Curve25519 key, hex or
	// base64).
	PrivKey string `json:"privkey"`

	// ---- client role ----

	// Server is the peer to tunnel to. ICMP binds no port, so a bare host is
	// the natural form; "host:port" is accepted and the port ignored.
	Server string `json:"server"`
	// ServerPub is the server's Noise static public key (hex or base64).
	// Empty selects PSK-only mode.
	ServerPub string `json:"server_pub"`
	// Listen is the local address applications connect to in CLI mode.
	Listen string `json:"listen"`

	// ---- shared ----

	// Passwords are the accepted PSKs. At least one non-blank is mandatory in
	// both roles.
	Passwords []string `json:"passwords"`
	// Magic overrides the record magic. Zero selects the default.
	Magic uint32 `json:"magic"`
	// SendWindow caps DATA records in flight (0 = default).
	SendWindow int `json:"send_window"`

	// Handshake tuning (client). The ICMP path often has a higher RTT and may
	// be rate-limited, so both are exposed.
	HandshakeAttempts  int `json:"handshake_attempts"`
	HandshakeBackoffMS int `json:"handshake_backoff_ms"`

	// ---- alias inputs, consumed only by UnmarshalJSON ----
	//
	// A single password is common enough that accepting `password` and `psk`
	// alongside `passwords` is worth the two fields. They are folded into
	// Passwords and then cleared so the rest of the program has one list.
	Password string     `json:"password"`
	PSK      stringList `json:"psk"`
}

// stringList accepts a JSON string OR an array of strings, which is what makes
// `"psk": "secret"` and `"psk": ["a", "b"]` both valid. Any other shape is a
// hard error: a silently-dropped credential is indistinguishable from a
// wrong PSK at the first handshake.
type stringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *stringList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return fmt.Errorf("psk: expected a string or an array of strings: %w", err)
		}
		*s = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return fmt.Errorf("psk: expected a string or an array of strings: %w", err)
	}
	*s = []string{one}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler. It exists solely to fold the
// `password` / `psk` aliases into `passwords`.
func (c *Config) UnmarshalJSON(data []byte) error {
	// A distinct type avoids recursing into this method.
	type plain Config
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*c = Config(p)
	all := append([]string(nil), c.Passwords...)
	if c.Password != "" {
		all = append(all, c.Password)
	}
	all = append(all, c.PSK...)
	c.Passwords = mergePasswords(all)
	c.Password = ""
	c.PSK = nil
	return nil
}

// mergePasswords trims, drops blanks, and de-duplicates preserving order.
// Repetition is not an error — the same PSK listed twice is a harmless typo —
// but it is not kept either, so the server never verifies a record against the
// same key twice.
func mergePasswords(lists ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, l := range lists {
		for _, s := range l {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// LoadConfig reads and parses a config file. `//` and `/* */` comments are
// accepted, because every documented example carries them and an operator will
// add them; they are stripped before JSON parsing.
//
// Unknown keys are deliberately NOT rejected — see the note on Config.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return ParseConfig(raw, path)
}

// ParseConfig parses config bytes. name is used only in error messages, so a
// caller that already has the bytes (a test, an embedded default) can use it
// without inventing a path.
func ParseConfig(raw []byte, name string) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(stripJSONComments(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", name, err)
	}
	return &cfg, nil
}

// stripJSONComments removes `//` line comments and `/* */` block comments
// without touching comment-like text inside string literals.
//
// It is a small scanner rather than a regexp on purpose: a regexp cannot know
// whether `//` sits inside a `"..."`, and a PSK or a target URL containing `//`
// (e.g. "tcp://host:22") is exactly that case. Getting this wrong would corrupt
// the very field that authenticates the tunnel.
func stripJSONComments(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	inString := false
	escaped := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if inString {
			out = append(out, ch)
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch {
		case ch == '"':
			inString = true
			out = append(out, ch)
		case ch == '/' && i+1 < len(raw) && raw[i+1] == '/':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			if i < len(raw) {
				out = append(out, '\n')
			}
		case ch == '/' && i+1 < len(raw) && raw[i+1] == '*':
			i += 2
			for i+1 < len(raw) && !(raw[i] == '*' && raw[i+1] == '/') {
				i++
			}
			i++ // land on the '/'; the loop's i++ moves past it
		default:
			out = append(out, ch)
		}
	}
	return out
}

// ServerConfig projects the config into the server's shape and validates the
// fields the server role cannot run without.
//
// Passwords are re-normalised here rather than trusted from UnmarshalJSON:
// this method is also reachable from a programmatically-built Config, and a
// list of blank strings must fail in the same place a missing list does.
func (c *Config) ServerConfig() (tunnel.ServerConfig, error) {
	sc := tunnel.ServerConfig{
		Transport:      c.Transport,
		ICMP:           c.ICMP,
		TargetAddr:     strings.TrimSpace(c.Target),
		Passwords:      mergePasswords(c.Passwords),
		Magic:          c.Magic,
		PrivateKey:     strings.TrimSpace(c.PrivKey),
		AllowedTargets: c.AllowedTargets,
		SendWindow:     c.SendWindow,
		LogLevel:       c.LogLevel,
	}
	if sc.TargetAddr == "" {
		return sc, fmt.Errorf("%w: server 'target' is required (e.g. \"tcp://127.0.0.1:22\"; use \"discard://\" for the MTU probe)", tunnel.ErrConfigRequired)
	}
	if len(sc.Passwords) == 0 {
		return sc, fmt.Errorf("%w: server 'passwords' is required (at least one PSK; run `gen-keys`/set a secret)", tunnel.ErrConfigRequired)
	}
	if err := c.ICMP.Validate(); err != nil {
		return sc, err
	}
	if _, err := tunnel.CheckTransport(c.Transport); err != nil {
		return sc, err
	}
	return sc, nil
}

// ClientConfig projects the config into the client's shape and validates the
// fields the client role cannot run without.
func (c *Config) ClientConfig() (tunnel.ClientConfig, error) {
	cc := tunnel.ClientConfig{
		Transport:         c.Transport,
		ICMP:              c.ICMP,
		ServerAddr:        strings.TrimSpace(c.Server),
		Target:            strings.TrimSpace(c.Target),
		Passwords:         mergePasswords(c.Passwords),
		Magic:             c.Magic,
		SendWindow:        c.SendWindow,
		ListenAddr:        strings.TrimSpace(c.Listen),
		LogLevel:          c.LogLevel,
		HandshakeAttempts: c.HandshakeAttempts,
	}
	if cc.ServerAddr == "" {
		return cc, fmt.Errorf("%w: client 'server' is required (the peer's address, e.g. \"203.0.113.7\")", tunnel.ErrConfigRequired)
	}
	if len(cc.Passwords) == 0 {
		return cc, fmt.Errorf("%w: client 'passwords' is required (must match the server's PSK)", tunnel.ErrConfigRequired)
	}
	if cc.ListenAddr == "" {
		return cc, fmt.Errorf("%w: client 'listen' is required for CLI mode (the local address applications connect to, e.g. \"127.0.0.1:1080\")", tunnel.ErrConfigRequired)
	}
	if c.HandshakeBackoffMS > 0 {
		cc.HandshakeBackoff = time.Duration(c.HandshakeBackoffMS) * time.Millisecond
	}
	if s := strings.TrimSpace(c.ServerPub); s != "" {
		key, err := tunnel.ParseNoiseKey(s)
		if err != nil {
			return cc, fmt.Errorf("client 'server_pub': %w", err)
		}
		cc.ServerPub = key
	}
	if err := c.ICMP.Validate(); err != nil {
		return cc, err
	}
	if _, err := tunnel.CheckTransport(c.Transport); err != nil {
		return cc, err
	}
	return cc, nil
}

// WriteTemplate writes the documented starter configuration for a role. It is
// what `gen-config` emits: a valid, commented file the operator edits.
func WriteTemplate(w io.Writer, role string) error {
	_, err := io.WriteString(w, templateFor(role))
	return err
}
