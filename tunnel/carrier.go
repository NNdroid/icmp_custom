package tunnel

import (
	"fmt"
	"strings"
	"time"
)

// Profile-default construction.
//
// Everything else in this package takes an injected Transport, which is what
// makes the session layer testable and embeddable. This file is the other
// half: the constructors that turn a parsed configuration into a live carrier,
// so `main.go` (and any embedder that does not own sockets itself) can build a
// working Server or Client from configuration alone.
//
// The rule it enforces: a transport that cannot exist must fail loudly at
// construction time, never silently at the first packet. That covers three
// distinct failures, each with its own actionable message —
//
//  1. an unsupported transport NAME ("udp" in a project with no UDP profile);
//  2. an unsupported PLATFORM (a raw ICMP carrier on Windows/macOS);
//  3. missing privileges (no CAP_NET_RAW) or a ping socket outside
//     net.ipv4.ping_group_range.
//
// (2) and (3) are raised by newPlatformICMPTransport, which knows the platform;
// (1) is raised here.

// TransportICMP is the transport profile this project implements. There is no
// UDP profile: `udp_custom` owns that, and a config that still says "udp" is a
// mistake, not a silent fallback to ICMP.
const TransportICMP = "icmp"

// resolveTransport validates and normalises a configured transport name. An
// empty value means "the only one there is", i.e. ICMP.
//
// The rejection deliberately names the accepted value: a config carried over
// from a UDP deployment should tell the operator what this build actually
// speaks instead of dying later with a socket error that looks unrelated.
func resolveTransport(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", TransportICMP:
		return TransportICMP, nil
	}
	return "", fmt.Errorf("%w: transport = %q (this build implements only %q)",
		ErrConfigRequired, name, TransportICMP)
}

// CheckTransport validates a configured transport name without opening
// anything. It is the exported half of resolveTransport, for a CLI that wants
// to reject a bad `transport` value while validating the whole config, before
// any socket exists.
func CheckTransport(name string) (string, error) { return resolveTransport(name) }

// NewServer builds a server on the ICMP carrier described by cfg, with a plain
// out-dial for forwarding targets.
func NewServer(cfg ServerConfig) (*Server, error) {
	return NewServerWithDialer(cfg, nil)
}

// NewServerWithDialer is NewServer with an injected TargetDialer, so an
// embedder can route the forwarding side through its own logic. A nil dialer
// falls back to a plain net.Dial against the granted target.
//
// The carrier is opened first and the session layer built second; if the
// session layer rejects the configuration (no password, a bad Noise key), the
// already-open carrier is closed, because a raw ICMP socket is a real kernel
// resource and leaking one per misconfiguration is not acceptable.
func NewServerWithDialer(cfg ServerConfig, dial TargetDialer) (*Server, error) {
	if _, err := resolveTransport(cfg.Transport); err != nil {
		return nil, err
	}
	logger := resolveLogger(cfg.Logger, cfg.LogLevel)
	tr, err := newICMPServerTransport(cfg.ICMP, logger)
	if err != nil {
		return nil, err
	}
	srv, err := NewServerWithTransport(cfg, tr, dial)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	return srv, nil
}

// NewClient builds a client on the ICMP carrier described by cfg.
//
// The ICMP profile is not just a carrier description: it also owns the poll
// schedule, because on a request-driven carrier the client's request window IS
// the downlink throughput ceiling. Those values are therefore copied onto the
// ClientConfig before the session layer is built. An explicitly-set
// ClientConfig field wins over the profile, so an embedder that builds the
// ClientConfig by hand is not surprised; the CLI path leaves them zero and
// gets the profile's values verbatim.
func NewClient(cfg ClientConfig) (*Client, error) {
	if _, err := resolveTransport(cfg.Transport); err != nil {
		return nil, err
	}
	// Validate the peer before touching a socket: an unparseable or missing
	// 'server' must not leave a raw socket half-open.
	peer, err := parsePeerAddr(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("client: invalid 'server' %q: %w", cfg.ServerAddr, err)
	}
	resolved, err := cfg.ICMP.resolve()
	if err != nil {
		return nil, err
	}
	applyICMPPollSchedule(&cfg, resolved)

	logger := resolveLogger(cfg.Logger, cfg.LogLevel)
	tr, err := newICMPClientTransport(cfg.ICMP, peer.Addr(), logger, cfg.ProtectFD)
	if err != nil {
		return nil, err
	}
	cli, err := NewClientWithTransport(cfg, tr)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	return cli, nil
}

// applyICMPPollSchedule maps the profile's poll tuning onto the generic
// ClientConfig fields the poll loop actually reads. Only zero-valued fields
// are filled: a caller that set one explicitly meant it.
func applyICMPPollSchedule(cfg *ClientConfig, p resolvedProfile) {
	if cfg.PollsInFlight == 0 {
		cfg.PollsInFlight = p.pollsInFlight
	}
	if cfg.PollInterval == 0 {
		// The active poll spacing must not be tighter than the carrier's own
		// pacing, or the session would queue requests the pacer then delays,
		// turning a smooth window into sawtooth. Aligning them is the whole
		// point of reading pace here.
		cfg.PollInterval = p.pace
	}
	if cfg.IdlePollInterval == 0 {
		cfg.IdlePollInterval = p.idlePoll
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = p.keepAlive
	}
}

// PollSchedule is the resolved poll timing the client will use. It is exposed
// so an operator (or a test) can see what the profile actually produced
// without re-deriving the defaults.
type PollSchedule struct {
	PollsInFlight int
	PollInterval  time.Duration
	IdlePoll      time.Duration
	KeepAlive     time.Duration
}

// PollSchedule reports the schedule the client will run with.
func (c *Client) PollSchedule() PollSchedule {
	return PollSchedule{
		PollsInFlight: c.cfg.pollsInFlight(),
		PollInterval:  c.cfg.pollInterval(),
		IdlePoll:      c.cfg.idlePoll(),
		KeepAlive:     c.cfg.keepAlive(),
	}
}
