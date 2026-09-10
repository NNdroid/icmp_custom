package tunnel

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// This file implements the standard Noise protocol handshake
//
//	Noise_NK_25519_ChaChaPoly_BLAKE2s
//
// as specified by the Noise Protocol Framework (revision 34). The message
// layout, hashing order (transcript), key derivation and Split() all follow the
// spec exactly.
//
// NK pattern (one round trip, responder's static key is known out of band —
// here: the server's `privkey`, published to clients as the Noise public key):
//
//	-> e, es   (client msg1: ephemeral + DH with the server's static key)
//	<- e, ee   (server msg2: ephemeral + DH between the two ephemerals)
//
// Both sides then Split() the chaining key into two transport keys:
// k1 (client -> server) and k2 (server -> client).
//
// DOCUMENTED DEVIATION (transport phase only): the spec calls for a
// monotonically increasing internal nonce per transport message. This protocol
// retransmits records, and a retransmitted record is byte-identical, so the
// receiver must be able to open the same (key, nonce, ciphertext) triple twice.
// We therefore derive the nonce from the record PacketNo — nonce =
// 00000000 || LE64(PacketNo) — which is exactly the QUIC/TLS record-protection
// pattern (RFC 9001 §5.3 derives a per-record nonce from the packet number).
// Keys, cipher and transcript are unchanged; only the nonce source differs, and
// protocol v2 additionally uses the record header as AAD.
const (
	// NoiseProtocolName is 33 bytes, i.e. longer than BLAKE2s' 32-byte hash
	// output, so the spec requires h = HASH(protocol_name) rather than the name
	// itself (names shorter than the hash length are zero-padded instead).
	NoiseProtocolName = "Noise_NK_25519_ChaChaPoly_BLAKE2s"

	// NoiseMsg1Size is the wire size of the client's handshake message:
	// ephemeral public key (32) + AEAD tag over the empty payload (16).
	NoiseMsg1Size = 32 + 16
	// NoiseMsg2Size is the wire size of the server's handshake message, same
	// layout as message 1.
	NoiseMsg2Size = 32 + 16
)

// NoiseKeyPair is a Curve25519 static key pair used to enable a Noise session.
// The private half stays on the server; the public half is published to
// clients out of band.
type NoiseKeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateNoiseKeyPair draws a fresh clamped Curve25519 static key pair.
func GenerateNoiseKeyPair() (*NoiseKeyPair, error) {
	var kp NoiseKeyPair
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, err
	}
	clampScalar(&kp.PrivateKey)

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PublicKey[:], pub)
	return &kp, nil
}

// clampScalar applies the Curve25519 bit-clamping required by GENERATE_KEYPAIR.
func clampScalar(k *[32]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// ParseNoiseKey accepts a 32-byte key as hex or base64 (standard or raw). A
// wrong length or a bad encoding is an error: a silently truncated key would
// make a mistyped config look like a working session.
func ParseNoiseKey(s string) ([32]byte, error) {
	var key [32]byte
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			copy(key[:], b)
			return key, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	return key, fmt.Errorf("%w: expected 32 bytes as hex or base64", ErrBadKey)
}

// FormatNoiseKey renders a key in both supported textual forms.
func FormatNoiseKey(key [32]byte) (hexStr, b64Str string) {
	return hex.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(key[:])
}

func blake2sHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// generateEphemeral returns a clamped Curve25519 keypair (GENERATE_KEYPAIR).
func generateEphemeral() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, err
	}
	clampScalar(&priv)
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], p)
	return priv, pub, nil
}

// dh performs DH and rejects a degenerate (all-zero) output, as required by
// the spec ("if the output is all-zero, abort").
func dh(priv, pub []byte) ([]byte, error) {
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	if subtleEqual(out, zero[:]) {
		return nil, errors.New("noise: degenerate DH output")
	}
	return out, nil
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// symmetricState is the Noise SymmetricState (spec §5.1): chaining key,
// handshake hash, cryptographic key and the handshake message nonce.
type symmetricState struct {
	ck   [32]byte
	h    [32]byte
	aead cipher.AEAD // nil until InitializeKey
	n    uint64      // reset to 0 by every InitializeKey
}

// newSymmetricState implements InitializeSymmetric(protocol_name):
//
//	if len(protocol_name) <= HASHLEN: h = protocol_name zero-padded to HASHLEN
//	else:                            h = HASH(protocol_name)
//
// and ck = h.
func newSymmetricState() *symmetricState {
	var h [32]byte
	if len(NoiseProtocolName) <= len(h) {
		copy(h[:], NoiseProtocolName)
	} else {
		hh := blake2sHash()
		_, _ = hh.Write([]byte(NoiseProtocolName))
		copy(h[:], hh.Sum(nil))
	}
	s := &symmetricState{ck: h, h: h}
	// The spec initialises with h = protocol_name and then immediately
	// MixHash(prologue). Our prologue is empty, but the MixHash still runs and
	// hashes h once — skipping it silently diverges from every conformant
	// implementation. Note that MixHash only advances h; ck stays as it was.
	s.mixHash(nil)
	return s
}

// nkInit builds the NK SymmetricState:
//
//	h  = HASH(protocol_name)      (name is 33 bytes, longer than the hash)
//	h  = HASH(h || prologue)      (prologue is empty for us)
//	h  = HASH(h || rs)            (responder's static key is a pre-message)
//	ck = HASH(protocol_name)      (unchanged by MixHash)
//
// Both peers must run all three hashing steps — the pre-message is what binds
// the handshake to the server's long-term key.
func nkInit(responderStaticPub []byte) *symmetricState {
	s := newSymmetricState()
	s.mixHash(responderStaticPub)
	return s
}

func (s *symmetricState) mixHash(data []byte) {
	h := blake2sHash()
	_, _ = h.Write(s.h[:])
	_, _ = h.Write(data)
	sum := h.Sum(nil)
	copy(s.h[:], sum)
}

// mixKey: HKDF(ck, ikm) → new ck + key (nonce resets to 0).
func (s *symmetricState) mixKey(ikm []byte) {
	kdf := hkdf.New(blake2sHash, ikm, s.ck[:], nil)
	out := make([]byte, 64)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic("noise: hkdf failed: " + err.Error())
	}
	copy(s.ck[:], out[:32])
	var key [32]byte
	copy(key[:], out[32:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("noise: chacha20poly1305 failed: " + err.Error())
	}
	s.aead = aead
	s.n = 0
}

func (s *symmetricState) handshakeNonce() []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], s.n)
	return nonce[:]
}

// encryptAndHash: ENCRYPT(k, n, ad=h, plaintext) then MixHash(ciphertext).
func (s *symmetricState) encryptAndHash(plaintext []byte) []byte {
	if s.aead == nil {
		out := append([]byte(nil), plaintext...)
		s.mixHash(out)
		return out
	}
	ct := s.aead.Seal(nil, s.handshakeNonce(), plaintext, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct
}

// decryptAndHash: DECRYPT(k, n, ad=h, ciphertext) then MixHash(ciphertext).
func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.aead == nil {
		s.mixHash(ciphertext)
		return ciphertext, nil
	}
	pt, err := s.aead.Open(nil, s.handshakeNonce(), ciphertext, s.h[:])
	if err != nil {
		return nil, err
	}
	s.n++
	s.mixHash(ciphertext)
	return pt, nil
}

// split: HKDF(ck, empty) → k1 (initiator -> responder), k2 (responder ->
// initiator).
func (s *symmetricState) split() (k1, k2 []byte) {
	kdf := hkdf.New(blake2sHash, nil, s.ck[:], nil)
	out := make([]byte, 64)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic("noise: hkdf failed: " + err.Error())
	}
	return out[:32], out[32:]
}

// NoiseCipherState wraps one ChaCha20-Poly1305 transport key.
type NoiseCipherState struct {
	aead cipher.AEAD
}

func newNoiseCipherState(key []byte) (*NoiseCipherState, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &NoiseCipherState{aead: aead}, nil
}

// packetNonce derives the 12-byte AEAD nonce from the 64-bit per-direction
// packet number: 00000000 || LE64(PacketNo). Retransmissions reuse the complete
// encoded record and therefore reuse only the exact same nonce/ciphertext pair.
//
// Why not a spec-style local counter: the receiver decrypts records in DELIVERY
// order, and the ARQ layer reorders (out-of-order records are buffered and
// drained later) and re-delivers (retransmissions). A counter synced to
// decryption order desyncs from the sender's encryption order on the first
// reordered packet, after which every record fails to open and the session is
// permanently stuck.
func packetNonce(packetNo uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], packetNo)
	return nonce
}

// Encrypt seals plaintext under this key with the record's packet number as
// nonce and aad as associated data.
func (s *NoiseCipherState) Encrypt(packetNo uint64, plaintext, aad []byte) []byte {
	nonce := packetNonce(packetNo)
	return s.aead.Seal(nil, nonce[:], plaintext, aad)
}

// Decrypt opens ciphertext under this key. A failure means the record was
// forged, corrupted or replayed under a different key.
func (s *NoiseCipherState) Decrypt(packetNo uint64, ciphertext, aad []byte) ([]byte, error) {
	nonce := packetNonce(packetNo)
	return s.aead.Open(nil, nonce[:], ciphertext, aad)
}

// SealRecordAEAD protects one complete session record. The encrypted payload
// has the same length as plaintext and Poly1305's 16-byte tag occupies the
// protocol trailer. Empty control-record payloads therefore cost exactly one
// tag and no second HMAC pass.
//
// limit is the carrier budget; a record that would exceed it returns nil so
// callers keep the "nil means unsendable" convention.
func SealRecordAEAD(r *Record, c *NoiseCipherState, plaintext []byte, limit int) []byte {
	if r == nil || c == nil || len(plaintext) > MaxPayloadLen {
		return nil
	}
	total := RecordHdrSize + len(plaintext) + chacha20poly1305.Overhead
	if limit > 0 && total > limit {
		return nil
	}
	wire := make([]byte, total)
	n := sealRecordAEADInto(wire, r, c, plaintext)
	return wire[:n]
}

// sealRecordAEADInto seals the record into the front of wire (which must have
// at least RecordHdrSize+len(plaintext)+Overhead capacity) and returns the used
// length: header + ciphertext, with the Poly1305 tag as the trailer.
func sealRecordAEADInto(wire []byte, r *Record, c *NoiseCipherState, plaintext []byte) int {
	header := wire[:RecordHdrSize]
	r.encodeHeaderInto(header, len(plaintext))
	nonce := packetNonce(r.PacketNo)
	sealed := c.aead.Seal(wire[RecordHdrSize:RecordHdrSize], nonce[:], plaintext, header)
	return RecordHdrSize + len(sealed)
}

// OpenRecordAEAD authenticates the received header and opens payload plus the
// trailer tag. It must run before any record field mutates session state.
func OpenRecordAEAD(r *Record, c *NoiseCipherState) ([]byte, error) {
	return OpenRecordAEADInto(nil, r, c)
}

// OpenRecordAEADInto is OpenRecordAEAD with a caller-provided output buffer: the
// plaintext is appended to dst, so a pooled buffer makes the receive path
// allocation-free. The result is only valid until dst is recycled.
func OpenRecordAEADInto(dst []byte, r *Record, c *NoiseCipherState) ([]byte, error) {
	if r == nil || c == nil || len(r.raw) < RecordMinSize {
		return nil, errors.New("noise: invalid record")
	}
	nonce := packetNonce(r.PacketNo)
	protected := r.raw[RecordHdrSize:]
	return c.aead.Open(dst[:0], nonce[:], protected, r.raw[:RecordHdrSize])
}

// NoiseSession is the result of a completed handshake.
type NoiseSession struct {
	SendCipher *NoiseCipherState
	RecvCipher *NoiseCipherState

	// HandshakeHash is the final handshake transcript hash h — the Noise
	// channel-binding value. It can be logged or compared out of band to bind
	// this session to the handshake that produced it.
	HandshakeHash [32]byte
}

func newNoiseSession(sendKey, recvKey []byte, h [32]byte) (*NoiseSession, error) {
	sendCipher, err := newNoiseCipherState(sendKey)
	if err != nil {
		return nil, err
	}
	recvCipher, err := newNoiseCipherState(recvKey)
	if err != nil {
		return nil, err
	}
	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher, HandshakeHash: h}, nil
}

// ClientNK is the initiator side of Noise_NK (the client). The server's static
// public key is known out of band.
type ClientNK struct {
	ss        *symmetricState
	ePriv     [32]byte
	ePub      [32]byte
	serverPub [32]byte
	msg1      []byte
	finished  bool
}

// NewClientNK starts the handshake: it generates the ephemeral keypair and
// processes the "e, es" tokens of message 1.
func NewClientNK(serverPub [32]byte) (*ClientNK, error) {
	c := &ClientNK{ss: nkInit(serverPub[:]), serverPub: serverPub}
	priv, pub, err := generateEphemeral()
	if err != nil {
		return nil, err
	}
	c.ePriv, c.ePub = priv, pub

	// -> e
	c.ss.mixHash(c.ePub[:])
	// -> es
	shared, err := dh(c.ePriv[:], serverPub[:])
	if err != nil {
		return nil, fmt.Errorf("noise: es: %w", err)
	}
	c.ss.mixKey(shared)
	return c, nil
}

// Message1 returns the 48-byte handshake message to send as the Noise part of
// the SYN payload (32B ephemeral + 16B AEAD tag over the empty payload). It is
// memoised: a retransmitted SYN must carry byte-identical Noise bytes.
func (c *ClientNK) Message1() ([]byte, error) {
	if c.msg1 == nil {
		tag := c.ss.encryptAndHash(nil)
		out := make([]byte, 0, NoiseMsg1Size)
		out = append(out, c.ePub[:]...)
		out = append(out, tag...)
		if len(out) != NoiseMsg1Size {
			return nil, fmt.Errorf("noise: unexpected msg1 size %d", len(out))
		}
		c.msg1 = out
	}
	return append([]byte(nil), c.msg1...), nil
}

// Finish processes msg2 ("e, ee"), verifies it, and returns the transport
// session. It must be called exactly once, with the ack payload the server
// sent in reply.
func (c *ClientNK) Finish(msg2 []byte) (*NoiseSession, error) {
	if c.finished {
		return nil, errors.New("noise: handshake already finished")
	}
	if len(msg2) != NoiseMsg2Size {
		return nil, fmt.Errorf("noise: msg2 is %d bytes, want %d", len(msg2), NoiseMsg2Size)
	}
	// <- e
	c.ss.mixHash(msg2[:32])
	// <- ee
	shared, err := dh(c.ePriv[:], msg2[:32])
	if err != nil {
		return nil, fmt.Errorf("noise: ee: %w", err)
	}
	c.ss.mixKey(shared)
	// payload (empty) — verifies the transcript up to here
	if _, err := c.ss.decryptAndHash(msg2[32:]); err != nil {
		return nil, fmt.Errorf("noise: msg2 authentication failed: %w", err)
	}
	k1, k2 := c.ss.split()
	sess, err := newNoiseSession(k1, k2, c.ss.h) // initiator: send k1, recv k2
	if err != nil {
		return nil, err
	}
	c.finished = true
	return sess, nil
}

// NewServerNoiseSession is the responder side of Noise_NK. It consumes the
// client's message 1 and returns the established session plus the 48-byte
// message 2 that must be delivered to the client (carried in the handshake ACK).
func NewServerNoiseSession(serverPrivkey [32]byte, msg1 []byte) (*NoiseSession, []byte, error) {
	if len(msg1) != NoiseMsg1Size {
		return nil, nil, fmt.Errorf("noise: msg1 is %d bytes, want %d", len(msg1), NoiseMsg1Size)
	}
	serverPub, err := curve25519.X25519(serverPrivkey[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	ss := nkInit(serverPub)

	// -> e
	ss.mixHash(msg1[:32])
	// -> es
	shared, err := dh(serverPrivkey[:], msg1[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("noise: es: %w", err)
	}
	ss.mixKey(shared)
	if _, err := ss.decryptAndHash(msg1[32:]); err != nil {
		return nil, nil, fmt.Errorf("noise: msg1 authentication failed: %w", err)
	}

	// <- e
	ePriv, ePub, err := generateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	ss.mixHash(ePub[:])
	// <- ee
	shared, err = dh(ePriv[:], msg1[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("noise: ee: %w", err)
	}
	ss.mixKey(shared)

	tag := ss.encryptAndHash(nil)
	msg2 := make([]byte, 0, NoiseMsg2Size)
	msg2 = append(msg2, ePub[:]...)
	msg2 = append(msg2, tag...)

	k1, k2 := ss.split()
	sess, err := newNoiseSession(k2, k1, ss.h) // responder: send k2, recv k1
	if err != nil {
		return nil, nil, err
	}
	return sess, msg2, nil
}
