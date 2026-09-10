package tunnel

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// The transport seam.
//
// Everything above this interface (record layer, ARQ, handshake, session table)
// is carrier-agnostic; everything below it knows how to move opaque record
// bytes. That split is why the same session layer can run over raw ICMP
// sockets, a non-root Android ping socket, or an in-memory pipe in a test.
//
// A Transport never inspects, re-frames or rewrites record contents: it hands
// back exactly the bytes it received, and it sends exactly the bytes it is
// given. Record sizing (the ICMP payload budget) is a carrier parameter
// reported through MaxRecordSizer, not a global constant.

// PathID is the transport-observed inbound channel key that MUST be mirrored on
// the reply. It collapses the old replyFromOrigPort(origPort, addr) triple into
// one transport-independent value:
//
//   - UDP-style carriers use Peer + Ident (Ident = the pre-DNAT destination
//     port of an origdst-style receiver).
//   - ICMP uses Peer + Ident (Echo Identifier) + Seq (the Echo sequence number
//     to echo back).
//
// A carrier fills only the fields it needs; a reply mirrors them verbatim so
// that whatever demultiplexing a NAT or the peer performed keeps working.
type PathID struct {
	// Peer is the peer's observed source address, as seen on the inbound
	// record. Replies to a peer-addressed record use it directly.
	Peer netip.AddrPort
	// Ident is the carrier's cheap inbound demultiplexing key: the ICMP Echo
	// Identifier. Zero when the carrier has none.
	Ident uint16
	// Seq is the extra key some request/reply carriers need to mirror: the ICMP
	// Echo sequence number. Zero when the carrier has none.
	Seq uint16
}

// Transport carries complete v2 records between an endpoint and the network.
//
// Implementations must be safe for one concurrent reader and one concurrent
// writer (the session layer drives exactly one of each), and Close must unblock
// a pending ReadRecord.
type Transport interface {
	// ReadRecord blocks until one inbound record arrives, copies it into buf,
	// and returns its length plus the path it arrived on.
	//
	// buf must be at least MaxRecordSize bytes when the carrier reports one; a
	// record that does not fit is a hard error rather than a silent truncation.
	ReadRecord(buf []byte) (int, PathID, error)

	// WriteRecord sends one record toward addr. It is used for the session's
	// first packet and for any peer-addressed traffic that has no observed path
	// yet.
	WriteRecord(rec []byte, to netip.AddrPort) error

	// ReplyRecord sends one record back along an observed path, mirroring
	// exactly the key the peer (and any NAT in between) expects to see.
	ReplyRecord(rec []byte, path PathID) error

	// LocalID and RemoteID are stable human-readable labels used only in logs.
	LocalID() string
	RemoteID() string

	// Close releases the carrier and unblocks any pending ReadRecord.
	Close() error
}

// MaxRecordSizer reports the largest complete v2 record this carrier can move.
// This is how the per-profile payload budget replaces a global max-packet
// constant: an ICMP carrier answers with its MTU-derived budget, a UDP carrier
// with its datagram budget, and a test carrier with whatever it was built with.
//
// The value is LIVE, not a constant: a carrier that adapts its budget (the ICMP
// profile's automatic MTU) returns its current estimate, so the session can
// re-read it and emit smaller or larger records without knowing why.
//
// A carrier that does not implement it is treated as "no carrier limit", i.e.
// only the uint16 PayloadLen field bounds a record.
type MaxRecordSizer interface {
	MaxRecordSize() int
}

// MaxReceiveSizer reports the largest record this carrier will ACCEPT from the
// peer.
//
// It is a separate capability from MaxRecordSizer because the two numbers are
// genuinely different. A path MTU is asymmetric, and a carrier whose own send
// budget adapts (the ICMP profile's automatic MTU) must still size its receive
// buffer for whatever the PEER may legitimately send. Sizing a receive buffer
// from your own send budget is how a tunnel ends up working perfectly in one
// direction and dying with "record too large" in the other.
//
// A carrier that does not implement it is treated as accepting whatever it can
// send, which is the right answer for a symmetric datagram carrier and for the
// in-memory test link.
type MaxReceiveSizer interface {
	MaxReceiveSize() int
}

// MTUFeedback is the reverse channel of MaxRecordSizer: a carrier that adapts
// its budget learns how big the records it carried actually turned out to be.
// It is what lets in-band path-MTU discovery work without any new wire format —
// the probe IS the data record, and the verdict IS the ACK.
//
// It is deliberately generic (it says nothing about ICMP), so a datagram
// carrier may implement it too. A carrier that does not implement it simply
// keeps a fixed budget.
type MTUFeedback interface {
	// RecordAcked reports that a record of this wire size was acknowledged by
	// the peer. Consecutive acks at the current ceiling are the signal to grow.
	RecordAcked(size int)
	// RecordLost reports that a record of this wire size exhausted its
	// retransmissions. Repeated losses at the same size are the signal to
	// shrink — but only after the smaller step has been shown to work, so a
	// transient black spot does not permanently shrink the budget.
	RecordLost(size int)
}

// AuthenticatedFeedback is implemented by carriers that classify their own
// health and therefore need to know when a record actually authenticated.
//
// It exists because that is the one event a carrier cannot observe for itself:
// a carrier sees bytes, not a successful AEAD tag. A request/reply carrier that
// never heard about authentication would either declare a working path blocked
// or unblock on forged traffic, and the difference between those two is the
// difference between a slow tunnel and a broken one.
type AuthenticatedFeedback interface {
	// RecordAuthenticated reports that a record passed verification.
	RecordAuthenticated()
}

// Poller is implemented by request-triggered carriers (ICMP Echo). Downlink can
// only be delivered in reply to a request, so the endpoint must emit polls.
// A datagram carrier such as UDP simply does not implement Poller, and the
// session layer then drives downlink by writing records directly.
type Poller interface {
	// Poke emits one carrier request (Echo Request) toward addr carrying
	// payload (normally a v2 PING/ACK record; may be empty) and returns the
	// carrier sequence number it used.
	Poke(payload []byte, to netip.AddrPort) (seq uint16, err error)
	// PollStats returns (pollsSent, repliesSeen) for carrier classification.
	PollStats() (pollsSent, repliesSeen uint64)
}

// Prober is the OPTIONAL server-initiated reverse probe (server -> client Echo
// Request). It is best-effort: whether an Echo Request even reaches a raw
// socket depends on the kernel (see DESIGN_ICMP.md §4.9), so implementations
// must be disableable and must degrade quietly on repeated failure. Android's
// ping-socket carrier does not implement it.
type Prober interface {
	Probe(payload []byte, to netip.AddrPort) error
}

// CarrierState classifies how the path under a carrier is behaving.
//
// It exists because a rate-limited path and a blocked one look identical to
// ARQ ("my packet was not acknowledged") but demand opposite reactions: a
// rate-limited path must be slowed down, while a blocked one must stop
// retransmitting entirely, because every retransmit is more fuel on a fire
// that is already being throttled — and on ICMP it also burns the host's
// global `icmp_msgs_per_sec` allowance, turning a temporary limit into a
// permanently lossy path.
type CarrierState int

const (
	// CarrierInit is the state before any evidence has arrived. The session
	// layer treats it exactly like CarrierUp: there is nothing to adapt to yet.
	CarrierInit CarrierState = iota
	// CarrierUp: authenticated traffic is flowing and loss is low.
	CarrierUp
	// CarrierThrottled: replies do arrive, but too few of them, or the RTT has
	// ballooned. The path works; something is rate-limiting it.
	CarrierThrottled
	// CarrierBlocked: requests go out and nothing at all comes back.
	CarrierBlocked
)

func (s CarrierState) String() string {
	switch s {
	case CarrierInit:
		return "init"
	case CarrierUp:
		return "up"
	case CarrierThrottled:
		return "throttled"
	case CarrierBlocked:
		return "blocked"
	}
	return "unknown"
}

// CarrierCondition is the optional capability a carrier uses to hand the
// session layer its timing constraints. A carrier that does not implement it
// leaves the session on its defaults — which is the right answer for the
// in-memory fake and for any datagram carrier, where an unacknowledged packet
// really does mean loss rather than "the path is being rate-limited".
type CarrierCondition interface {
	// CarrierState reports the current classification.
	CarrierState() CarrierState
	// RTOFloor is the smallest retransmit timeout that is meaningful right
	// now. A path that cannot answer faster than its own pacing interval, or
	// that is currently black-holed, is only amplified by a shorter timer, so
	// the session must never use one.
	RTOFloor() time.Duration
}

// TargetDialer dials the real backend service a session forwards to. It is
// injected so the same session layer works with a real network, an in-process
// sink, or a test stub.
type TargetDialer func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error)

// maxRecordSizeOf reports the carrier's budget, or 0 when it declares none.
func maxRecordSizeOf(tr Transport) int {
	if s, ok := tr.(MaxRecordSizer); ok {
		return s.MaxRecordSize()
	}
	return 0
}

// maxReceiveSizeOf reports the largest record the carrier will accept from the
// peer. Carriers that do not distinguish the directions accept what they send.
func maxReceiveSizeOf(tr Transport) int {
	if s, ok := tr.(MaxReceiveSizer); ok {
		if n := s.MaxReceiveSize(); n > 0 {
			return n
		}
	}
	return maxRecordSizeOf(tr)
}

// pollerOf returns the carrier's Poller, or nil when it is not
// request-triggered. Callers must nil-check before use.
func pollerOf(tr Transport) Poller {
	if p, ok := tr.(Poller); ok {
		return p
	}
	return nil
}

// proberOf returns the carrier's optional Prober, or nil when reverse probing
// is unsupported (or deliberately disabled by not implementing it).
func proberOf(tr Transport) Prober {
	if p, ok := tr.(Prober); ok {
		return p
	}
	return nil
}

// carrierConditionOf returns the carrier's optional CarrierCondition, or nil
// when it declares no timing constraints of its own.
func carrierConditionOf(tr Transport) CarrierCondition {
	if c, ok := tr.(CarrierCondition); ok {
		return c
	}
	return nil
}

// defaultRTOFloor is the retransmit floor used when a carrier declares none.
// It matches the historical RTO estimator seed, so carriers that don't opt in
// behave exactly as before.
const defaultRTOFloor = 200 * time.Millisecond

// rtoFloorOf reports the carrier's current retransmit floor, falling back to
// defaultRTOFloor. Callers on a hot path should cache the CarrierCondition
// instead of re-asserting per packet.
func rtoFloorOf(tr Transport) time.Duration {
	if c := carrierConditionOf(tr); c != nil {
		if floor := c.RTOFloor(); floor > 0 {
			return floor
		}
	}
	return defaultRTOFloor
}

// payloadBudgetOf reports the largest plaintext payload the carrier can carry
// RIGHT NOW. fallback is used when the carrier declares no budget.
//
// The session layer calls this on every send instead of caching the value,
// which is what makes an adaptive carrier transparent: the ICMP profile's
// automatic MTU shrinks and grows the records the session emits without the
// session containing a single line about MTUs.
func payloadBudgetOf(tr Transport, fallback int) int {
	if s, ok := tr.(MaxRecordSizer); ok {
		if limit := s.MaxRecordSize(); limit > 0 {
			if p := MaxPayloadFor(limit); p > 0 {
				return p
			}
		}
	}
	return fallback
}

// mtuFeedbackOf returns the carrier's optional MTUFeedback, or nil when its
// budget is fixed.
func mtuFeedbackOf(tr Transport) MTUFeedback {
	if f, ok := tr.(MTUFeedback); ok {
		return f
	}
	return nil
}

// authenticatedFeedbackOf returns the carrier's optional AuthenticatedFeedback,
// or nil when it does not classify its own health.
func authenticatedFeedbackOf(tr Transport) AuthenticatedFeedback {
	if f, ok := tr.(AuthenticatedFeedback); ok {
		return f
	}
	return nil
}
