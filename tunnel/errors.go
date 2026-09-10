package tunnel

import "errors"

// Sentinel errors shared across the package. Callers use errors.Is on these,
// so every wrapped error must keep the sentinel in its chain.
var (
	// ErrClosed is returned once Close has been called.
	ErrClosed = errors.New("tunnel: closed")

	// ErrNoRoute is returned when a carrier has no usable path to the peer.
	ErrNoRoute = errors.New("tunnel: no route to peer")

	// ErrTunnelClosed is the base reason reported by TunnelSession.Err.
	ErrTunnelClosed = errors.New("tunnel: session closed")

	// ErrTransportUnsupported is returned when the configured transport cannot
	// exist on the current platform. It is always accompanied by an actionable
	// hint in the wrapping message.
	ErrTransportUnsupported = errors.New("transport: unsupported on this platform")

	// ErrHandshakeTimeout is returned when the peer never answers a SYN.
	// Because every handshake failure is a silent drop, this single error
	// covers an unreachable peer, a PSK mismatch and a target denied by the
	// server's allowed_targets filter; the wrapping message lists all three so
	// the operator is not left guessing.
	ErrHandshakeTimeout = errors.New("handshake: no reply from peer")

	// ErrNonceCollision reports two concurrent handshakes drawing the same
	// client nonce. It is astronomically unlikely (128 bits) and indicates a
	// broken entropy source rather than a protocol problem.
	ErrNonceCollision = errors.New("handshake: client nonce already in flight")

	// ErrNoCapNetRaw is the Linux privilege failure of a raw ICMP socket. The
	// wrapping message always names CAP_NET_RAW and the setcap command.
	ErrNoCapNetRaw = errors.New("icmp: raw ICMP socket requires CAP_NET_RAW (or root)")

	// ErrPingSocketDenied is the Android failure when net.ipv4.ping_group_range
	// does not cover the process. The wrapping message names the sysctl.
	ErrPingSocketDenied = errors.New("icmp: ping socket denied by net.ipv4.ping_group_range")

	// ErrBadKey reports a malformed or unusable static key.
	ErrBadKey = errors.New("key: invalid static key")

	// ErrNoiseRequired reports a Noise-mode call made without a static key.
	ErrNoiseRequired = errors.New("noise: static key is required")

	// ErrRecordTooLarge reports a record that does not fit the carrier's
	// budget. It is raised at encode time rather than left to the socket.
	ErrRecordTooLarge = errors.New("record: exceeds carrier payload budget")

	// ErrMessageTooLarge reports a framed message bigger than the assembler
	// limit; a desynchronised stream cannot be resynchronised safely.
	ErrMessageTooLarge = errors.New("framing: message exceeds maximum size")

	// ErrAssemblerBroken is returned after a length error until Reset.
	ErrAssemblerBroken = errors.New("framing: assembler broken, call Reset()")

	// ErrConfigRequired reports a missing mandatory configuration value.
	ErrConfigRequired = errors.New("config: required field is missing")
)
