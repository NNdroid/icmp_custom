package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCryptoHandshakeKeysDirectionSeparated(t *testing.T) {
	var nonce [ClientNonceSize]byte
	copy(nonce[:], "0123456789abcdef")
	keys := DerivePSKHandshakeKeys("psk-1", nonce)
	if bytes.Equal(keys.SynMAC[:], keys.AckMAC[:]) {
		t.Fatal("SYN and ACK MAC keys must differ")
	}
	again := DerivePSKHandshakeKeys("psk-1", nonce)
	if !bytes.Equal(keys.SynMAC[:], again.SynMAC[:]) || !bytes.Equal(keys.AckMAC[:], again.AckMAC[:]) {
		t.Fatal("handshake derivation must be deterministic")
	}
}

func TestCryptoHandshakeKeysBoundToNonceAndPSK(t *testing.T) {
	var nonce [ClientNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	base := DerivePSKHandshakeKeys("psk-1", nonce)

	otherNonce := nonce
	otherNonce[0] ^= 1
	otherKeys := DerivePSKHandshakeKeys("psk-1", otherNonce)
	otherPSK := DerivePSKHandshakeKeys("psk-2", nonce)
	if bytes.Equal(base.SynMAC[:], otherKeys.SynMAC[:]) {
		t.Fatal("handshake key is not bound to the client nonce")
	}
	if bytes.Equal(base.SynMAC[:], otherPSK.SynMAC[:]) {
		t.Fatal("handshake key is not bound to the PSK")
	}
}

func TestCryptoSessionKeysBoundToTranscript(t *testing.T) {
	var clientNonce [ClientNonceSize]byte
	var serverNonce [ServerNonceSize]byte
	copy(clientNonce[:], "client-nonce-0001")
	copy(serverNonce[:], "server-nonce-0001")

	base := DerivePSKSessionKeys("psk", clientNonce, serverNonce, 1)
	if bytes.Equal(base.C2S[:], base.S2C[:]) {
		t.Fatal("C2S and S2C must differ")
	}
	repeated := DerivePSKSessionKeys("psk", clientNonce, serverNonce, 1)
	if !bytes.Equal(base.C2S[:], repeated.C2S[:]) {
		t.Fatal("session derivation must be deterministic")
	}

	differentPSK := DerivePSKSessionKeys("psk2", clientNonce, serverNonce, 1)
	diffClient := clientNonce
	diffClient[0] ^= 0xFF
	diffServer := serverNonce
	diffServer[0] ^= 0xFF

	for name, got := range map[string][32]byte{
		"psk":        differentPSK.C2S,
		"client":     DerivePSKSessionKeys("psk", diffClient, serverNonce, 1).C2S,
		"server":     DerivePSKSessionKeys("psk", clientNonce, diffServer, 1).C2S,
		"session-id": DerivePSKSessionKeys("psk", clientNonce, serverNonce, 2).C2S,
	} {
		if bytes.Equal(base.C2S[:], got[:]) {
			t.Fatalf("session key was not bound to the %s input", name)
		}
	}
}

// TestCryptoDomainSeparation checks that the handshake and session key
// schedules never produce the same material, so a handshake MAC key can never
// be confused with a record key.
func TestCryptoDomainSeparation(t *testing.T) {
	var nonce [ClientNonceSize]byte
	var serverNonce [ServerNonceSize]byte
	copy(nonce[:], "domain-separation")
	copy(serverNonce[:], "domain-separation")
	hs := DerivePSKHandshakeKeys("psk", nonce)
	ss := DerivePSKSessionKeys("psk", nonce, serverNonce, 1)
	if bytes.Equal(hs.SynMAC[:], ss.C2S[:]) || bytes.Equal(hs.SynMAC[:], ss.S2C[:]) ||
		bytes.Equal(hs.AckMAC[:], ss.C2S[:]) || bytes.Equal(hs.AckMAC[:], ss.S2C[:]) {
		t.Fatal("handshake and session key schedules collided")
	}
}

func TestCryptoFrameCiphersAreMirrored(t *testing.T) {
	var clientNonce [ClientNonceSize]byte
	var serverNonce [ServerNonceSize]byte
	copy(clientNonce[:], "mirror-client-01")
	copy(serverNonce[:], "mirror-server-01")
	keys := DerivePSKSessionKeys("psk", clientNonce, serverNonce, 9)

	client, err := keys.ClientFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}
	server, err := keys.ServerFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}

	rec := &Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 9, PacketNo: 1, Seq: 1}
	wire := SealRecordAEAD(rec, client.Send, []byte("c2s"), 0)
	parsed, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenRecordAEAD(parsed, server.Recv)
	if err != nil || string(plain) != "c2s" {
		t.Fatalf("server failed to open a client record: %q %v", plain, err)
	}

	// And the reverse direction.
	back := &Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 9, PacketNo: 1, Seq: 1}
	wire = SealRecordAEAD(back, server.Send, []byte("s2c"), 0)
	parsed, err = ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = OpenRecordAEAD(parsed, client.Recv)
	if err != nil || string(plain) != "s2c" {
		t.Fatalf("client failed to open a server record: %q %v", plain, err)
	}
}

func TestCryptoMatchSynPSK(t *testing.T) {
	passwords := []string{"alpha", "beta", "gamma"}
	wire, clientNonce, _ := buildTestSYN(t, "beta", nil)

	if got := matchSynPSK(wire, passwords, clientNonce); got != "beta" {
		t.Fatalf("matchSynPSK = %q, want beta", got)
	}
	if got := matchSynPSK(wire, []string{"alpha", "gamma"}, clientNonce); got != "" {
		t.Fatalf("matchSynPSK = %q, want empty when no candidate matches", got)
	}
	// A tampered SYN matches nothing.
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 1
	if got := matchSynPSK(tampered, passwords, clientNonce); got != "" {
		t.Fatalf("tampered SYN matched %q", got)
	}
}
