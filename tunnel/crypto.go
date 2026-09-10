package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// PSK key schedule.
//
// The handshake (SYN/ACK) is HMAC-SHA256-128 protected; every established
// record is ChaCha20-Poly1305 sealed. Both key sets derive from the shared PSK
// with HKDF-SHA256, but through SEPARATE info strings, and every key is bound
// to the handshake transcript (the fresh client nonce, or both nonces plus the
// SessionID). The consequences, in order of importance:
//
//   - SYN and ACK keys are distinct, so a SYN can never be replayed as an ACK;
//   - the two record directions get independent keys, so a record can never be
//     reflected back at its sender and open successfully;
//   - a PSK shared by two deployments never yields the same key material,
//     because the info strings are project-scoped ("icmp_custom/...").
//
// The info strings deliberately carry the project name rather than the shared
// wire magic: the magic is a rotation-friendly prefilter, not an identity, and
// key material must not silently change when an operator rotates it.
const (
	handshakeKeysInfo = "icmp_custom/v2/handshake-keys"
	sessionKeysInfo   = "icmp_custom/v2/session-keys-aead"
)

// PSKHandshakeKeys holds the direction-separated handshake MAC keys derived
// from the PSK and the fresh client nonce. The server tries SynMAC on inbound
// SYNs; the client verifies AckMAC on inbound ACKs.
type PSKHandshakeKeys struct {
	SynMAC [32]byte
	AckMAC [32]byte
}

// PSKSessionKeys holds the ChaCha20-Poly1305 record keys of a PSK-only
// session. C2S authenticates AND encrypts client→server records, S2C the
// reverse direction; both are bound to the PSK, both handshake nonces and the
// SessionID. PSK-only records therefore use exactly the same wire format as
// Noise records (header as AAD, Poly1305 tag in the trailer) — they just lack
// Noise's forward secrecy, because the keys derive from the long-lived PSK.
type PSKSessionKeys struct {
	C2S [32]byte
	S2C [32]byte
}

// DerivePSKHandshakeKeys binds direction-separated SYN/ACK keys to the fresh
// client nonce. HKDF with SHA-256 cannot fail given a 16-byte salt, so a
// failure here is a programming error and panics rather than silently
// degrading to a zero key.
func DerivePSKHandshakeKeys(psk string, clientNonce [ClientNonceSize]byte) PSKHandshakeKeys {
	kdf := hkdf.New(sha256.New, []byte(psk), clientNonce[:], []byte(handshakeKeysInfo))
	var material [64]byte
	if _, err := io.ReadFull(kdf, material[:]); err != nil {
		panic("icmp_custom: handshake HKDF failed: " + err.Error())
	}
	var out PSKHandshakeKeys
	copy(out.SynMAC[:], material[:32])
	copy(out.AckMAC[:], material[32:])
	return out
}

// DerivePSKSessionKeys binds traffic keys to both peers' nonces and the
// SessionID. The salt is a hash of the three so the derivation stays a
// single HKDF step regardless of how the caller orders them.
func DerivePSKSessionKeys(psk string, clientNonce [ClientNonceSize]byte, serverNonce [ServerNonceSize]byte, sessionID uint32) PSKSessionKeys {
	var saltInput [ClientNonceSize + ServerNonceSize + 4]byte
	copy(saltInput[:ClientNonceSize], clientNonce[:])
	copy(saltInput[ClientNonceSize:ClientNonceSize+ServerNonceSize], serverNonce[:])
	binary.BigEndian.PutUint32(saltInput[ClientNonceSize+ServerNonceSize:], sessionID)
	salt := sha256.Sum256(saltInput[:])

	kdf := hkdf.New(sha256.New, []byte(psk), salt[:], []byte(sessionKeysInfo))
	var material [64]byte
	if _, err := io.ReadFull(kdf, material[:]); err != nil {
		panic("icmp_custom: session HKDF failed: " + err.Error())
	}
	var out PSKSessionKeys
	copy(out.C2S[:], material[:32])
	copy(out.S2C[:], material[32:])
	return out
}

// FrameKeys holds the two per-direction record-protection cipher states of an
// established session, from the perspective of the holder: Send seals outgoing
// records (ChaCha20-Poly1305: confidentiality + authenticity), Recv opens
// incoming ones. Direction separation defeats reflection. Both PSK-only and
// Noise sessions use this same record format; they differ only in key
// material (PSK-derived vs forward-secret) — a PSK leak never enables
// forgery, but unlike Noise it does expose past traffic.
type FrameKeys struct {
	Send *NoiseCipherState
	Recv *NoiseCipherState
}

// ClientFrameCiphers builds the client-side FrameKeys: the client seals with
// C2S and opens with S2C.
func (k PSKSessionKeys) ClientFrameCiphers() (*FrameKeys, error) {
	send, err := newNoiseCipherState(k.C2S[:])
	if err != nil {
		return nil, err
	}
	recv, err := newNoiseCipherState(k.S2C[:])
	if err != nil {
		return nil, err
	}
	return &FrameKeys{Send: send, Recv: recv}, nil
}

// ServerFrameCiphers builds the server-side FrameKeys: the server seals with
// S2C and opens with C2S.
func (k PSKSessionKeys) ServerFrameCiphers() (*FrameKeys, error) {
	send, err := newNoiseCipherState(k.S2C[:])
	if err != nil {
		return nil, err
	}
	recv, err := newNoiseCipherState(k.C2S[:])
	if err != nil {
		return nil, err
	}
	return &FrameKeys{Send: send, Recv: recv}, nil
}

// matchSynPSK returns the configured PSK whose SYN MAC key validates wire, or
// the empty string when none does. Trying each candidate is what lets a server
// hold several credentials at once without leaking which one matched: every
// failure returns the same nil error to the caller.
func matchSynPSK(wire []byte, passwords []string, clientNonce [ClientNonceSize]byte) string {
	for _, psk := range passwords {
		keys := DerivePSKHandshakeKeys(psk, clientNonce)
		if VerifyMAC(wire, &keys.SynMAC, 0) == nil {
			return psk
		}
	}
	return ""
}
