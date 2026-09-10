// Package tunnel implements the icmp_custom v2 tunnel protocol: an
// authenticated, reliable, multiplexed channel carried over ICMP Echo
// Request/Reply.
//
// The package is layered so that the record format is completely independent of
// the carrier that moves the records:
//
//	L1 record core   protocol.go crypto.go noise.go framing.go
//	                 replay.go rtt_estimator.go logger.go errors.go
//	                 -- pure byte-level protocol; no sockets, no transport
//	L2 transport     transport.go
//	                 -- the Transport seam every carrier implements
//	L3 carriers      icmp_linux.go icmp_other.go icmp_android.go icmpprofile.go
//	                 -- ICMP carriers (raw sockets / ping sockets)
//	L4 session       server.go client.go events.go autoreconnect.go
//	                 -- handshake, ARQ, per-session target forwarding
//
// A record is always exactly `RecordHdrSize + PayloadLen + RecordTagSize`
// bytes. The ICMP carrier transmits a complete record verbatim as the ICMP
// payload: there is no ICMP-specific header and no padding. The largest record
// a carrier can move is a profile parameter, reported through
// MaxRecordSizer.MaxRecordSize, because the ICMP payload budget is smaller than
// what a UDP carrier would allow.
package tunnel
