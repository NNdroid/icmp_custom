package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Wire constants of protocol v2.
//
// A record is exactly RecordHdrSize + PayloadLen + RecordTagSize bytes, all
// integers in network byte order. The layout is fixed and transport
// independent: an ICMP carrier puts a complete record, byte for byte, in the
// ICMP payload.
const (
	// MagicDefault is the default record magic.
	//
	// The magic is transmitted in the clear (it is part of the AEAD associated
	// data, not of the ciphertext), so it must NOT be a printable word: an
	// ASCII tag such as "UDPC" is a fingerprint that a middlebox can match with
	// a plain string rule. This value is deliberately outside the ASCII range
	// and is not a well-known hash constant. Operators should override it per
	// deployment through the config file and rotate it when needed.
	//
	// The magic is a cheap prefilter, never a security boundary: authenticity
	// and confidentiality come from the AEAD tag and the replay window.
	MagicDefault = uint32(0xA7C3E519)

	// ZeroMagic is the sentinel that disables the magic check on receive. A
	// configured magic must therefore never be zero.
	ZeroMagic = uint32(0)

	// Version is the only protocol version this package speaks. There is no v1
	// compatibility mode and v1 records are rejected structurally.
	Version = uint8(0x02)

	// RecordHdrSize is the fixed header size.
	RecordHdrSize = 40
	// RecordTagSize is the authentication trailer: an HMAC-SHA256-128 for
	// SYN/ACK and a Poly1305 tag for every established record.
	RecordTagSize = 16
	// RecordMACSize is the truncated HMAC length.
	RecordMACSize = RecordTagSize
	// RecordMinSize is the smallest possible record (empty payload).
	RecordMinSize = RecordHdrSize + RecordTagSize
	// MaxPayloadLen is the largest payload the uint16 PayloadLen field can
	// describe. The effective per-carrier budget is smaller; see
	// MaxPayloadFor.
	MaxPayloadLen = int(^uint16(0))
)

// Command types. The numeric values are wire values.
const (
	CmdHandshakeSyn  = uint8(0x01)
	CmdHandshakeAck  = uint8(0x02)
	CmdData          = uint8(0x03)
	CmdAck           = uint8(0x04)
	CmdPing          = uint8(0x05)
	CmdPong          = uint8(0x06)
	CmdFin           = uint8(0x07)
	CmdPathChallenge = uint8(0x08)
	CmdPathResponse  = uint8(0x09)
)

const (
	// ClientNonceSize and ServerNonceSize are the handshake nonce lengths.
	ClientNonceSize = 16
	ServerNonceSize = 16

	// SynPayloadBase is the fixed part of a SYN payload:
	// ClientNonce || UnixTimestamp.
	SynPayloadBase = ClientNonceSize + 8

	// AckPayloadBase is the fixed part of a handshake ACK payload:
	// ClientNonce || ServerNonce.
	AckPayloadBase = ClientNonceSize + ServerNonceSize

	// TargetTLVLen is the 2-byte big-endian length prefix of a target TLVs.
	TargetTLVLen = 2

	// TargetMaxLen bounds a requested or granted endpoint string. Generous:
	// even "tcp://very-long-hostname.example.internal:65535" is far below it.
	TargetMaxLen = 255

	// PathChallengeSize is the fixed payload of a path-validation record.
	PathChallengeSize = 16
)

// MaxPayloadFor converts a carrier's maximum record size into the largest
// plaintext payload that still fits. A limit <= 0 means "no carrier limit", in
// which case only the uint16 wire field bounds the payload.
func MaxPayloadFor(limit int) int {
	if limit <= 0 {
		return MaxPayloadLen
	}
	if limit < RecordMinSize {
		return 0
	}
	return limit - RecordHdrSize - RecordTagSize
}

// Record is one decoded v2 record.
//
// Raw is the complete wire form of a RECEIVED record (header + payload + tag).
// It borrows the caller's read buffer, so it must not be retained past the
// dispatch that produced it: the MAC input is Raw minus the trailer and the
// AEAD associated data is Raw's header.
type Record struct {
	Magic      uint32
	Version    uint8
	Cmd        uint8
	Flags      uint16
	SessionID  uint32
	PacketNo   uint64
	Seq        uint64
	Ack        uint64
	WindowSize uint16
	Data       []byte

	raw []byte
}

// Raw returns the received wire bytes of the record, or nil for a record that
// was built rather than parsed.
func (r *Record) Raw() []byte { return r.raw }

// PayloadLen reports the payload length as it appears on the wire.
func (r *Record) PayloadLen() int { return len(r.Data) }

func (r *Record) encodeHeaderInto(buf []byte, dataLen int) {
	binary.BigEndian.PutUint32(buf[0:4], r.Magic)
	buf[4] = r.Version
	buf[5] = r.Cmd
	binary.BigEndian.PutUint16(buf[6:8], r.Flags)
	binary.BigEndian.PutUint32(buf[8:12], r.SessionID)
	binary.BigEndian.PutUint64(buf[12:20], r.PacketNo)
	binary.BigEndian.PutUint64(buf[20:28], r.Seq)
	binary.BigEndian.PutUint64(buf[28:36], r.Ack)
	binary.BigEndian.PutUint16(buf[36:38], r.WindowSize)
	binary.BigEndian.PutUint16(buf[38:40], uint16(dataLen))
}

// Marshal builds the unsealed wire form of the record. The zeroed
// authentication trailer must be filled by SealMAC or SealAEADInto before the
// record is sent; an unsealed record is never accepted by a receive path.
//
// limit is the carrier's maximum record size (MaxRecordSize). A positive limit
// that the record exceeds is rejected here, at encode time, rather than being
// left to fail at the socket as a truncated write.
func (r *Record) Marshal(limit int) ([]byte, error) {
	if r == nil {
		return nil, errors.New("tunnel: nil record")
	}
	if len(r.Data) > MaxPayloadLen {
		return nil, fmt.Errorf("tunnel: payload length %d exceeds the uint16 wire field", len(r.Data))
	}
	total := RecordHdrSize + len(r.Data) + RecordTagSize
	if limit > 0 && total > limit {
		return nil, fmt.Errorf("%w: need %d bytes, carrier budget is %d", ErrRecordTooLarge, total, limit)
	}
	wire := make([]byte, total)
	r.encodeHeaderInto(wire[:RecordHdrSize], len(r.Data))
	copy(wire[RecordHdrSize:], r.Data)
	return wire, nil
}

// Parse decodes a record structurally into dst, borrowing buf (dst.raw aliases
// buf). It performs no authentication; callers must follow with VerifyMAC or
// OpenAEADInto before touching session state.
//
// limit is the carrier's maximum record size; a record larger than the budget
// of the carrier it arrived on is a structural error.
func Parse(buf []byte, magic uint32, limit int, dst *Record) error {
	if len(buf) < RecordMinSize {
		return errors.New("tunnel: record shorter than header plus tag")
	}
	if limit > 0 && len(buf) > limit {
		return fmt.Errorf("%w: %d > %d", ErrRecordTooLarge, len(buf), limit)
	}
	if buf[4] != Version {
		return fmt.Errorf("tunnel: unsupported protocol version 0x%02X", buf[4])
	}
	got := binary.BigEndian.Uint32(buf[0:4])
	if magic != ZeroMagic && got != magic {
		return errors.New("tunnel: magic mismatch")
	}
	if !validCommand(buf[5]) {
		return fmt.Errorf("tunnel: unknown command 0x%02X", buf[5])
	}
	dataLen := int(binary.BigEndian.Uint16(buf[38:40]))
	if len(buf) != RecordHdrSize+dataLen+RecordTagSize {
		return fmt.Errorf("tunnel: payload length mismatch (field %d, buffer %d)", dataLen, len(buf))
	}

	*dst = Record{
		Magic:      got,
		Version:    buf[4],
		Cmd:        buf[5],
		Flags:      binary.BigEndian.Uint16(buf[6:8]),
		SessionID:  binary.BigEndian.Uint32(buf[8:12]),
		PacketNo:   binary.BigEndian.Uint64(buf[12:20]),
		Seq:        binary.BigEndian.Uint64(buf[20:28]),
		Ack:        binary.BigEndian.Uint64(buf[28:36]),
		WindowSize: binary.BigEndian.Uint16(buf[36:38]),
		raw:        buf[:len(buf):len(buf)],
	}
	if dataLen > 0 {
		dst.Data = buf[RecordHdrSize : RecordHdrSize+dataLen]
	} else {
		dst.Data = nil
	}
	return nil
}

// ParseOwned decodes a record and copies it so the caller may release buf. Use
// it only when the record must outlive the read buffer (for example a SYN
// handed to an asynchronous handshake goroutine).
func ParseOwned(buf []byte, magic uint32, limit int) (*Record, error) {
	var rec Record
	if err := Parse(buf, magic, limit, &rec); err != nil {
		return nil, err
	}
	dataLen := len(rec.Data)
	rec.raw = append([]byte(nil), rec.raw...)
	if dataLen > 0 {
		rec.Data = rec.raw[RecordHdrSize : RecordHdrSize+dataLen]
	}
	return &rec, nil
}

func validCommand(cmd uint8) bool {
	return cmd >= CmdHandshakeSyn && cmd <= CmdPathResponse
}

// validSessionRecordShape reports whether a record has the field shape its
// command requires. It is a structural check only: authentication and the
// replay window are applied afterwards, and no session state may change before
// all three succeed.
//
// Every established record needs a non-zero SessionID and PacketNo. DATA
// additionally needs a non-zero Seq; the control records carry no payload and
// no Seq; path-validation records carry exactly PathChallengeSize bytes.
func validSessionRecordShape(r *Record) bool {
	if r == nil || r.SessionID == 0 || r.PacketNo == 0 {
		return false
	}
	switch r.Cmd {
	case CmdData:
		return r.Seq != 0
	case CmdAck, CmdPing, CmdPong, CmdFin:
		return r.Seq == 0 && len(r.Data) == 0
	case CmdPathChallenge, CmdPathResponse:
		return r.Seq == 0 && len(r.Data) == PathChallengeSize
	default:
		return false
	}
}

// frameMACInto writes HMAC-SHA256-128(key, msg) into dst.
func frameMACInto(dst []byte, key *[32]byte, msg []byte) {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write(msg)
	var sum [sha256.Size]byte
	copy(dst, h.Sum(sum[:0])[:RecordMACSize])
}

// macWire authenticates header plus payload in place, writing the 16-byte tag
// into the trailer.
func macWire(wire []byte, key *[32]byte) error {
	if key == nil {
		return errors.New("tunnel: record MAC key is required")
	}
	if len(wire) < RecordMinSize {
		return errors.New("tunnel: record shorter than header plus tag")
	}
	msg := wire[:len(wire)-RecordTagSize]
	frameMACInto(wire[len(msg):], key, msg)
	return nil
}

// SealMAC builds and authenticates a handshake record (SYN or ACK) with
// HMAC-SHA256-128. It returns nil on failure so callers can keep the
// "nil means unsendable" convention.
func SealMAC(r *Record, key *[32]byte, limit int) []byte {
	wire, err := r.Marshal(limit)
	if err != nil {
		return nil
	}
	if err := macWire(wire, key); err != nil {
		return nil
	}
	return wire
}

// VerifyMAC verifies a handshake record. Only SYN and ACK are HMAC protected;
// every established record is an AEAD record (see OpenAEADInto).
func VerifyMAC(wire []byte, key *[32]byte, limit int) error {
	if key == nil {
		return errors.New("tunnel: record MAC key is required")
	}
	if len(wire) < RecordMinSize {
		return errors.New("tunnel: record shorter than header plus tag")
	}
	if limit > 0 && len(wire) > limit {
		return fmt.Errorf("%w: %d > %d", ErrRecordTooLarge, len(wire), limit)
	}
	msg := wire[:len(wire)-RecordTagSize]
	var expected [RecordMACSize]byte
	frameMACInto(expected[:], key, msg)
	if !hmac.Equal(wire[len(msg):], expected[:]) {
		return errors.New("tunnel: record MAC mismatch")
	}
	return nil
}

// appendTargetTLV appends the optional length-prefixed endpoint field to a
// handshake payload. An empty target appends nothing, which is the wire form of
// "use the peer's default target".
func appendTargetTLV(payload []byte, target string) []byte {
	if target == "" || len(target) > TargetMaxLen {
		return payload
	}
	var l [TargetTLVLen]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(target)))
	payload = append(payload, l[:]...)
	return append(payload, target...)
}

// TargetTLV returns the exact bytes a target string encodes to on the wire.
// The handshake uses it to verify that a SYN carries no bytes beyond the base
// payload, the target and an optional Noise message.
func TargetTLV(target string) []byte {
	if target == "" || len(target) > TargetMaxLen {
		return nil
	}
	var l [TargetTLVLen]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(target)))
	return append(l[:], target...)
}

// parseTargetTLV decodes one optional target field. ok is false when the field
// is empty (TLV absent) or malformed.
func parseTargetTLV(field []byte) (target string, ok bool) {
	if len(field) < TargetTLVLen {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(field[:TargetTLVLen]))
	if n == 0 || n > TargetMaxLen || len(field) != TargetTLVLen+n {
		return "", false
	}
	return string(field[TargetTLVLen:]), true
}

// splitSynPayload splits a SYN payload into the optional requested target and
// the optional Noise message 1, which is always the LAST NoiseMsg1Size bytes.
// A payload of just the base part requests the default target.
func splitSynPayload(data []byte, hasNoise bool) (target string, msg1 []byte, err error) {
	if len(data) < SynPayloadBase {
		return "", nil, errors.New("tunnel: SYN payload too short")
	}
	rest := data[SynPayloadBase:]
	if hasNoise {
		if len(rest) < NoiseMsg1Size {
			return "", nil, errors.New("tunnel: SYN is missing the Noise message 1")
		}
		msg1 = rest[len(rest)-NoiseMsg1Size:]
		rest = rest[:len(rest)-NoiseMsg1Size]
	}
	if len(rest) > 0 {
		t, ok := parseTargetTLV(rest)
		if !ok {
			return "", nil, errors.New("tunnel: invalid target request field")
		}
		target = t
	}
	return target, msg1, nil
}

// splitAckPayload splits a handshake ACK payload into the optional granted
// target and the optional Noise message 2 (the LAST NoiseMsg2Size bytes). An
// ACK without the TLV grants the default target.
func splitAckPayload(data []byte, hasNoise bool) (granted string, msg2 []byte, err error) {
	if len(data) < AckPayloadBase {
		return "", nil, errors.New("tunnel: ACK payload too short")
	}
	rest := data[AckPayloadBase:]
	if hasNoise {
		if len(rest) < NoiseMsg2Size {
			return "", nil, errors.New("tunnel: ACK is missing the Noise message 2")
		}
		msg2 = rest[len(rest)-NoiseMsg2Size:]
		rest = rest[:len(rest)-NoiseMsg2Size]
	}
	if len(rest) > 0 {
		t, ok := parseTargetTLV(rest)
		if !ok {
			return "", nil, errors.New("tunnel: invalid granted target field")
		}
		granted = t
	}
	return granted, msg2, nil
}

// ParseTargetNetworkAndAddr splits a "tcp://host:port" / "udp://host:port"
// endpoint into its network and address. An endpoint without a scheme is
// treated as TCP. Matching is case-insensitive on the scheme only; the address
// is returned verbatim.
//
// "discard://" names the server's in-process sink (see discard.go). It is
// recognised here so that a requested `discard://…` target reaches
// ServerSession's sink branch instead of being handed to the dialer as a bogus
// hostname.
func ParseTargetNetworkAndAddr(raw string) (network, address string) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "udp://"):
		return "udp", raw[len("udp://"):]
	case strings.HasPrefix(lower, "tcp://"):
		return "tcp", raw[len("tcp://"):]
	case strings.HasPrefix(lower, "discard://"):
		return "discard", raw[len("discard://"):]
	default:
		return "tcp", raw
	}
}
