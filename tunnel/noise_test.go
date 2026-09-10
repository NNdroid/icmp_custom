package tunnel

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// completeNoiseHandshake drives a full NK handshake and returns both sides'
// sessions plus the raw messages, so tests can assert on the transcript too.
func completeNoiseHandshake(t *testing.T) (*NoiseSession, *NoiseSession, []byte, []byte) {
	t.Helper()
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := client.Message1()
	if err != nil {
		t.Fatal(err)
	}
	server, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
	if err != nil {
		t.Fatalf("server failed to process msg1: %v", err)
	}
	csess, err := client.Finish(msg2)
	if err != nil {
		t.Fatalf("client failed to process msg2: %v", err)
	}
	return csess, server, msg1, msg2
}

func TestNoiseHandshakeEstablishesTransportKeys(t *testing.T) {
	client, server, msg1, msg2 := completeNoiseHandshake(t)
	if len(msg1) != NoiseMsg1Size {
		t.Fatalf("msg1 size = %d, want %d", len(msg1), NoiseMsg1Size)
	}
	if len(msg2) != NoiseMsg2Size {
		t.Fatalf("msg2 size = %d, want %d", len(msg2), NoiseMsg2Size)
	}
	if client.HandshakeHash != server.HandshakeHash {
		t.Fatal("both sides must agree on the handshake hash")
	}

	// client -> server
	rec := &Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1}
	wire := SealRecordAEAD(rec, client.SendCipher, []byte("hello-server"), 0)
	parsed, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenRecordAEAD(parsed, server.RecvCipher)
	if err != nil || string(plain) != "hello-server" {
		t.Fatalf("server could not open client record: %q %v", plain, err)
	}

	// server -> client
	rec2 := &Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1}
	wire = SealRecordAEAD(rec2, server.SendCipher, []byte("hello-client"), 0)
	parsed, err = ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = OpenRecordAEAD(parsed, client.RecvCipher)
	if err != nil || string(plain) != "hello-client" {
		t.Fatalf("client could not open server record: %q %v", plain, err)
	}

	// Direction keys must not be interchangeable.
	parsed, _ = ParseOwned(SealRecordAEAD(rec, client.SendCipher, []byte("x"), 0), MagicDefault, 0)
	if _, err := OpenRecordAEAD(parsed, client.RecvCipher); err == nil {
		t.Fatal("client recv key opened a client-send record")
	}
}

func TestNoiseHandshakeHashBindsSession(t *testing.T) {
	c1, _, _, _ := completeNoiseHandshake(t)
	c2, _, _, _ := completeNoiseHandshake(t)
	if c1.HandshakeHash == c2.HandshakeHash {
		t.Fatal("two independent handshakes must produce different transcript hashes")
	}
}

func TestNoiseMessage1IsStable(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	client, _ := NewClientNK(kp.PublicKey)
	a, err := client.Message1()
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Message1()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Message1 must be memoised: a retransmitted SYN needs identical bytes")
	}
}

func TestNoiseRejectsTamperedMsg1(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	client, _ := NewClientNK(kp.PublicKey)
	msg1, _ := client.Message1()
	// Flip a bit inside the AEAD tag over the empty payload.
	msg1[len(msg1)-1] ^= 1
	if _, _, err := NewServerNoiseSession(kp.PrivateKey, msg1); err == nil {
		t.Fatal("tampered msg1 authenticated")
	}
}

func TestNoiseRejectsTamperedMsg2(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	client, _ := NewClientNK(kp.PublicKey)
	msg1, _ := client.Message1()
	_, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
	if err != nil {
		t.Fatal(err)
	}
	msg2[len(msg2)-1] ^= 1
	if _, err := client.Finish(msg2); err == nil {
		t.Fatal("tampered msg2 authenticated")
	}
}

func TestNoiseWrongServerKeyFails(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	wrong, _ := GenerateNoiseKeyPair()
	client, _ := NewClientNK(kp.PublicKey)
	msg1, _ := client.Message1()
	if _, _, err := NewServerNoiseSession(wrong.PrivateKey, msg1); err == nil {
		t.Fatal("a server with the wrong static key accepted msg1")
	}
}

func TestNoiseFinishOnlyOnce(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	client, _ := NewClientNK(kp.PublicKey)
	msg1, _ := client.Message1()
	_, msg2, _ := NewServerNoiseSession(kp.PrivateKey, msg1)
	if _, err := client.Finish(msg2); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Finish(msg2); err == nil {
		t.Fatal("Finish must refuse a second call")
	}
}

func TestNoiseMessageSizeValidation(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	if _, _, err := NewServerNoiseSession(kp.PrivateKey, make([]byte, NoiseMsg1Size-1)); err == nil {
		t.Fatal("short msg1 must be rejected")
	}
	client, _ := NewClientNK(kp.PublicKey)
	if _, err := client.Finish(make([]byte, NoiseMsg2Size-1)); err == nil {
		t.Fatal("short msg2 must be rejected")
	}
}

func TestNoiseKeyPairPublicDerivesFromPrivate(t *testing.T) {
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, kp.PublicKey[:]) {
		t.Fatal("published public key does not match the private key")
	}
}

func TestNoiseKeyParseAndFormat(t *testing.T) {
	kp, _ := GenerateNoiseKeyPair()
	hexStr, b64Str := FormatNoiseKey(kp.PublicKey)

	got, err := ParseNoiseKey(hexStr)
	if err != nil || got != kp.PublicKey {
		t.Fatalf("hex round trip failed: %v", err)
	}
	got, err = ParseNoiseKey(b64Str)
	if err != nil || got != kp.PublicKey {
		t.Fatalf("base64 round trip failed: %v", err)
	}
	got, err = ParseNoiseKey("  " + hexStr + "  ")
	if err != nil || got != kp.PublicKey {
		t.Fatalf("trimmed hex round trip failed: %v", err)
	}
	if _, err := ParseNoiseKey("not-a-key"); err == nil {
		t.Fatal("garbage key must be rejected")
	}
	if _, err := ParseNoiseKey("aabb"); err == nil {
		t.Fatal("short key must be rejected")
	}
}
