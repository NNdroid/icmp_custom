package tunnel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The profile-default constructors are the bridge from a config file to a live
// carrier. Two things about them are worth pinning down, because both are easy
// to regress without any test failing:
//
//  1. ORDERING. A bad peer or profile must be rejected before a socket is
//     opened and before the platform is consulted. Otherwise a typo'd value on
//     Linux would surface as a confusing CAP_NET_RAW error, and on Windows as
//     a platform error that hides the real mistake.
//
//  2. MAPPING. The ICMP profile owns the poll schedule, because on a
//     request-driven carrier the request window IS the downlink ceiling. The
//     mapping must fill only unset fields, so an embedder's explicit values
//     survive.

// A malformed profile must be rejected before the platform is consulted:
// otherwise a `max_payload` typo would be reported as "no ICMP carrier on
// windows" on a Windows dev box, which sends the operator down the wrong path.
func TestNewClientRejectsBadProfileBeforeTouchingThePlatform(t *testing.T) {
	for name, prof := range map[string]ICMPProfile{
		"max_payload too large": {MaxPayload: 9999},
		"mtu_min above budget":  {MaxPayload: 1200, MTUMin: 1300},
		"mtu_mode unknown":      {MTUMode: "guess"},
		"pace_ms zero":          {PaceMS: -1},
		"id_range bad":          {IDRange: "abc"},
		"block_timeout bad":     {BlockTimeout: "not-a-duration"},
	} {
		_, err := NewClient(ClientConfig{
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
	if err := (ICMPProfile{MTUMode: "ipv7"}).Validate(); err == nil {
		t.Fatal("Validate accepted an unknown mtu_mode")
	} else if !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("Validate error %v does not wrap ErrConfigRequired", err)
	}
	// Validate must apply the same defaults resolve does, including the single
	// family-independent ceiling: the dual-stack safe value is accepted, the
	// IPv4-only ceiling it replaced is now rejected.
	if err := (ICMPProfile{MaxPayload: icmpV6MaxPayload}).Validate(); err != nil {
		t.Fatalf("the dual-stack ceiling must validate: %v", err)
	}
	if err := (ICMPProfile{MaxPayload: icmpV4MaxPayload}).Validate(); err == nil {
		t.Fatalf("IPv4's %d is above the dual-stack ceiling and must be rejected", icmpV4MaxPayload)
	}
}

// The SYN rate limiter is the one gate an unauthenticated sender can drive, so
// its memory must be bounded: a spoofed-source flood that keeps creating
// buckets would otherwise be a slow remote memory DoS. The cap is FAIL-CLOSED
// — new sources are refused while the table is full, live sources keep their
// buckets, and pruning frees room for genuinely new sources.
func TestSynLimiterCapsTheBucketTableAndKeepsLiveSources(t *testing.T) {
	l := newSynLimiter(1000, 1)
	now := time.Now()

	for i := 0; i < synBucketCap; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		if !l.Allow(ip, now) {
			t.Fatalf("source %s refused before the cap was reached", ip)
		}
	}
	if l.Len() != synBucketCap {
		t.Fatalf("table holds %d buckets, want %d", l.Len(), synBucketCap)
	}

	if l.Allow("10.200.0.1", now) {
		t.Fatal("a new source was admitted while the table was full")
	}
	if n := l.Rejected(); n != 1 {
		t.Fatalf("Rejected = %d, want 1", n)
	}

	// A source that was already talking keeps working: its bucket refills.
	if !l.Allow("10.0.0.1", now.Add(time.Second)) {
		t.Fatal("an existing live source was refused while under its rate")
	}

	// Pruning frees room for genuinely new sources: backdate one bucket's
	// last-touched time past the idle TTL and the next new source is admitted.
	l.mu.Lock()
	l.buckets["10.0.2.1"].last = now.Add(-2 * time.Minute)
	l.mu.Unlock()
	if !l.Allow("10.200.0.2", now.Add(time.Second)) {
		t.Fatal("a new source was refused although an idle bucket was prunable")
	}
}

// A portless allowed_targets pattern silently widens to EVERY port on the
// hosts it names ("tcp://*" grants all TCP everywhere). The construction-time
// warning is what keeps that widening from being a surprise — and fully
// spelled-out patterns must stay quiet.
func TestAllowedTargetPatternWarnings(t *testing.T) {
	cEp, sEp := newFakeLink("client", "server", testRecordLimit)
	defer cEp.Close()

	logs := &captureLogger{}
	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://127.0.0.1:22",
		Passwords:  []string{"secret"},
		AllowedTargets: []string{
			"tcp://*",          // portless: grants every port via the fallback
			"tcp://10.0.0.6",   // portless, no wildcard: never matches
			"tcp://10.0.0.5:*", // explicit port wildcard: normal semantics, quiet
			"tcp://10.0.0.7:22",
		},
		Logger: logs,
	}, sEp, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	defer srv.Close()

	// Only the TRULY portless pattern widens: "10.0.0.5:*" spells its port
	// out (as the wildcard) and takes the normal host+port matching path, so
	// it must stay quiet.
	if logs.find(`"tcp://*"`) == "" {
		t.Fatal("a portless wildcard pattern must draw the every-port warning")
	}
	if logs.find(`"tcp://10.0.0.6"`) == "" {
		t.Fatal("a portless pattern without wildcards must draw the never-match warning")
	}
	if logs.find(`"tcp://10.0.0.5:*"`) != "" || logs.find(`"tcp://10.0.0.7:22"`) != "" {
		t.Fatal("a pattern with an explicit port must not draw a warning")
	}
}
