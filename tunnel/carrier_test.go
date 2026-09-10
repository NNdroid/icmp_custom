package tunnel

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The profile-default constructors are the bridge from a config file to a live
// carrier. Two things about them are worth pinning down, because both are easy
// to regress without any test failing:
//
//  1. ORDERING. An unsupported transport NAME must be rejected before a socket
//     is opened, and before the platform is consulted. Otherwise a typo'd
//     `transport` on Linux would surface as a confusing CAP_NET_RAW error, and
//     on Windows as a platform error that hides the real mistake.
//
//  2. MAPPING. The ICMP profile owns the poll schedule, because on a
//     request-driven carrier the request window IS the downlink ceiling. The
//     mapping must fill only unset fields, so an embedder's explicit values
//     survive.

func TestResolveTransportAcceptsOnlyICMP(t *testing.T) {
	accepted := []string{"", "icmp", "ICMP", " icmp ", "Icmp", "\ticmp\n"}
	for _, in := range accepted {
		got, err := resolveTransport(in)
		if err != nil {
			t.Fatalf("resolveTransport(%q) returned error: %v", in, err)
		}
		if got != TransportICMP {
			t.Fatalf("resolveTransport(%q) = %q, want %q", in, got, TransportICMP)
		}
	}

	// Every rejection must keep the sentinel in the chain and name both the
	// offending value and the accepted one, so the operator is never left
	// guessing what this build speaks.
	for _, in := range []string{"udp", "UDP", "tcp", "discard", "icmp2", "icmpv6"} {
		_, err := resolveTransport(in)
		if err == nil {
			t.Fatalf("resolveTransport(%q) unexpectedly succeeded", in)
		}
		if !errors.Is(err, ErrConfigRequired) {
			t.Fatalf("resolveTransport(%q) error %v does not wrap ErrConfigRequired", in, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, in) {
			t.Fatalf("resolveTransport(%q) error %q does not quote the offending value", in, msg)
		}
		if !strings.Contains(msg, TransportICMP) {
			t.Fatalf("resolveTransport(%q) error %q does not name %q", in, msg, TransportICMP)
		}
	}
}

func TestCheckTransportMatchesTheUnexportedResolver(t *testing.T) {
	for _, in := range []string{"", "icmp", "udp", " ICMP "} {
		wantName, wantErr := resolveTransport(in)
		gotName, gotErr := CheckTransport(in)
		if gotName != wantName {
			t.Fatalf("CheckTransport(%q) name = %q, want %q", in, gotName, wantName)
		}
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("CheckTransport(%q) err = %v, resolveTransport err = %v", in, gotErr, wantErr)
		}
		if gotErr != nil && !errors.Is(gotErr, ErrConfigRequired) {
			t.Fatalf("CheckTransport(%q) error %v does not wrap ErrConfigRequired", in, gotErr)
		}
	}
}

// The distinguishing assertion is the NEGATIVE one: an unsupported transport
// has to produce a config error and NOT the sentinel that means "this platform
// has no ICMP carrier". If the ordering ever flips, this test fails on every
// platform, including the ones where the carrier would build fine.
func TestNewServerRejectsUnknownTransportBeforeTouchingThePlatform(t *testing.T) {
	_, err := NewServer(ServerConfig{
		Transport:  "udp",
		TargetAddr: "tcp://127.0.0.1:22",
		Passwords:  []string{"secret"},
	})
	if err == nil {
		t.Fatal("NewServer accepted transport \"udp\"")
	}
	if !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("error %v does not wrap ErrConfigRequired", err)
	}
	if errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("error %v is a platform error; the transport name must be checked first", err)
	}
	if !strings.Contains(err.Error(), "udp") {
		t.Fatalf("error %q does not quote the offending transport", err)
	}
}

func TestNewClientRejectsUnknownTransportBeforeTouchingThePlatform(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Transport:  "udp",
		ServerAddr: "203.0.113.9",
		Passwords:  []string{"secret"},
		ListenAddr: "127.0.0.1:1080",
	})
	if err == nil {
		t.Fatal("NewClient accepted transport \"udp\"")
	}
	if !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("error %v does not wrap ErrConfigRequired", err)
	}
	if errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("error %v is a platform error; the transport name must be checked first", err)
	}
}

// A malformed profile must be rejected before the platform is consulted too:
// otherwise a `max_payload` typo would be reported as "no ICMP carrier on
// windows" on a Windows dev box, which sends the operator down the wrong path.
func TestNewClientRejectsBadProfileBeforeTouchingThePlatform(t *testing.T) {
	for name, prof := range map[string]ICMPProfile{
		"max_payload too large": {MaxPayload: 9999},
		"family unknown":        {Family: "ipv5"},
		"mtu_min above budget":  {MaxPayload: 1200, MTUMin: 1300},
		"mtu_mode unknown":      {MTUMode: "guess"},
		"pace_ms zero":          {PaceMS: -1},
		"id_range bad":          {IDRange: "abc"},
		"block_timeout bad":     {BlockTimeout: "not-a-duration"},
	} {
		_, err := NewClient(ClientConfig{
			Transport:  TransportICMP,
			ICMP:       prof,
			ServerAddr: "203.0.113.9",
			Passwords:  []string{"secret"},
			ListenAddr: "127.0.0.1:1080",
		})
		if err == nil {
			t.Fatalf("%s: NewClient accepted an invalid profile", name)
		}
		if !errors.Is(err, ErrConfigRequired) {
			t.Fatalf("%s: error %v does not wrap ErrConfigRequired", name, err)
		}
		if errors.Is(err, ErrTransportUnsupported) {
			t.Fatalf("%s: error %v is a platform error; profile validation must come first", name, err)
		}
	}
}

func TestNewClientRejectsMissingServerBeforeTouchingThePlatform(t *testing.T) {
	_, err := NewClient(ClientConfig{
		Transport:  TransportICMP,
		ServerAddr: "   ",
		Passwords:  []string{"secret"},
		ListenAddr: "127.0.0.1:1080",
	})
	if err == nil {
		t.Fatal("NewClient accepted an empty 'server'")
	}
	if errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("error %v is a platform error; the peer must be validated first", err)
	}
	if !strings.Contains(err.Error(), "server") {
		t.Fatalf("error %q does not name the missing 'server' field", err)
	}
}

func TestApplyICMPPollScheduleFillsOnlyZeroFields(t *testing.T) {
	resolved := resolvedProfile{
		pollsInFlight: 8,
		pace:          33 * time.Millisecond,
		idlePoll:      777 * time.Millisecond,
		keepAlive:     9 * time.Second,
	}

	t.Run("empty client config takes the profile verbatim", func(t *testing.T) {
		var cfg ClientConfig
		applyICMPPollSchedule(&cfg, resolved)
		if cfg.PollsInFlight != 8 {
			t.Fatalf("PollsInFlight = %d, want 8", cfg.PollsInFlight)
		}
		if cfg.PollInterval != 33*time.Millisecond {
			t.Fatalf("PollInterval = %v, want 33ms", cfg.PollInterval)
		}
		if cfg.IdlePollInterval != 777*time.Millisecond {
			t.Fatalf("IdlePollInterval = %v, want 777ms", cfg.IdlePollInterval)
		}
		if cfg.KeepAlive != 9*time.Second {
			t.Fatalf("KeepAlive = %v, want 9s", cfg.KeepAlive)
		}
	})

	t.Run("an explicit client config wins", func(t *testing.T) {
		cfg := ClientConfig{
			PollsInFlight:    2,
			PollInterval:     5 * time.Millisecond,
			IdlePollInterval: 100 * time.Millisecond,
			KeepAlive:        time.Minute,
		}
		applyICMPPollSchedule(&cfg, resolved)
		if cfg.PollsInFlight != 2 {
			t.Fatalf("PollsInFlight = %d, want the explicit 2", cfg.PollsInFlight)
		}
		if cfg.PollInterval != 5*time.Millisecond {
			t.Fatalf("PollInterval = %v, want the explicit 5ms", cfg.PollInterval)
		}
		if cfg.IdlePollInterval != 100*time.Millisecond {
			t.Fatalf("IdlePollInterval = %v, want the explicit 100ms", cfg.IdlePollInterval)
		}
		if cfg.KeepAlive != time.Minute {
			t.Fatalf("KeepAlive = %v, want the explicit 1m", cfg.KeepAlive)
		}
	})
}

// The default profile must reproduce the client's historical defaults, so
// introducing the profile did not silently change the poll cadence.
func TestApplyICMPPollScheduleReproducesTheClientDefaults(t *testing.T) {
	resolved, err := (ICMPProfile{}).resolve()
	if err != nil {
		t.Fatalf("default profile failed to resolve: %v", err)
	}
	var cfg ClientConfig
	applyICMPPollSchedule(&cfg, resolved)

	got := PollSchedule{
		PollsInFlight: cfg.pollsInFlight(),
		PollInterval:  cfg.pollInterval(),
		IdlePoll:      cfg.idlePoll(),
		KeepAlive:     cfg.keepAlive(),
	}
	want := PollSchedule{
		PollsInFlight: defaultPollsInFlight,
		PollInterval:  defaultPollInterval,
		IdlePoll:      defaultIdlePollInterval,
		KeepAlive:     defaultKeepAlive,
	}
	if got != want {
		t.Fatalf("default profile produced %+v, want the client defaults %+v", got, want)
	}
}

func TestClientPollScheduleReflectsTheProfile(t *testing.T) {
	a, _ := newFakeLink("client", "server", 2048)
	defer a.Close()

	cli, err := NewClientWithTransport(ClientConfig{
		Transport:  TransportICMP,
		ICMP:       ICMPProfile{PollsInFlight: 6, PaceMS: 30, IdlePollMS: 250, KeepAliveMS: 3000},
		ServerAddr: "203.0.113.9",
		Passwords:  []string{"secret"},
		ListenAddr: "127.0.0.1:1080",
	}, a)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	defer cli.Close()

	// NewClientWithTransport does not map the profile: it takes the carrier as
	// given. Mapping is NewClient's job, so apply it here to observe the pair
	// the CLI path would produce.
	resolved, err := cli.cfg.ICMP.resolve()
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	cfg := cli.cfg
	applyICMPPollSchedule(&cfg, resolved)

	got := PollSchedule{
		PollsInFlight: cfg.pollsInFlight(),
		PollInterval:  cfg.pollInterval(),
		IdlePoll:      cfg.idlePoll(),
		KeepAlive:     cfg.keepAlive(),
	}
	want := PollSchedule{
		PollsInFlight: 6,
		PollInterval:  30 * time.Millisecond,
		IdlePoll:      250 * time.Millisecond,
		KeepAlive:     3 * time.Second,
	}
	if got != want {
		t.Fatalf("PollSchedule = %+v, want %+v", got, want)
	}
}

func TestICMPProfileValidateMirrorsResolve(t *testing.T) {
	if err := (ICMPProfile{}).Validate(); err != nil {
		t.Fatalf("the zero profile must validate (it is the default profile): %v", err)
	}
	if err := (ICMPProfile{Family: "ipv7"}).Validate(); err == nil {
		t.Fatal("Validate accepted an unknown family")
	} else if !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("Validate error %v does not wrap ErrConfigRequired", err)
	}
	// Validate must apply the same defaults resolve does: an explicit budget
	// equal to the default must be accepted for both families.
	if err := (ICMPProfile{Family: "ipv6", MaxPayload: icmpV6MaxPayload}).Validate(); err != nil {
		t.Fatalf("IPv6 ceiling rejected: %v", err)
	}
	if err := (ICMPProfile{Family: "ipv4", MaxPayload: icmpV6MaxPayload}).Validate(); err != nil {
		t.Fatalf("IPv4 accepts up to %d and the IPv6 ceiling is smaller: %v", icmpV4MaxPayload, err)
	}
}
