package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// buildTestSYN constructs the only handshake form accepted by protocol v2.
func buildTestSYN(tb testing.TB, psk string, noiseMsg1 []byte) ([]byte, [ClientNonceSize]byte, PSKHandshakeKeys) {
	tb.Helper()
	var clientNonce [ClientNonceSize]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		tb.Fatal(err)
	}
	payload := make([]byte, SynPayloadBase+len(noiseMsg1))
	copy(payload[:ClientNonceSize], clientNonce[:])
	binary.BigEndian.PutUint64(payload[ClientNonceSize:SynPayloadBase], uint64(time.Now().Unix()))
	copy(payload[SynPayloadBase:], noiseMsg1)
	keys := DerivePSKHandshakeKeys(psk, clientNonce)
	wire := SealMAC(&Record{
		Magic: MagicDefault, Version: Version,
		Cmd: CmdHandshakeSyn, Data: payload,
	}, &keys.SynMAC, 0)
	if len(wire) == 0 {
		tb.Fatal("failed to seal test SYN")
	}
	return wire, clientNonce, keys
}

func testClientFrameKeys(tb testing.TB, psk string, clientNonce [ClientNonceSize]byte, serverNonce [ServerNonceSize]byte, sid uint32) *FrameKeys {
	tb.Helper()
	keys := DerivePSKSessionKeys(psk, clientNonce, serverNonce, sid)
	fk, err := keys.ClientFrameCiphers()
	if err != nil {
		tb.Fatalf("client frame ciphers: %v", err)
	}
	return fk
}

func commandName(cmd uint8) string {
	switch cmd {
	case CmdHandshakeSyn:
		return "SYN"
	case CmdHandshakeAck:
		return "ACK_HANDSHAKE"
	case CmdData:
		return "DATA"
	case CmdAck:
		return "ACK"
	case CmdPing:
		return "PING"
	case CmdPong:
		return "PONG"
	case CmdFin:
		return "FIN"
	case CmdPathChallenge:
		return "PATH_CHALLENGE"
	case CmdPathResponse:
		return "PATH_RESPONSE"
	default:
		return "UNKNOWN"
	}
}

func TestProtocolV2HeaderRoundTrip64Bit(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	want := &Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdData,
		Flags: 0x1234, SessionID: 0xaabbccdd,
		PacketNo: 1<<48 + 7, Seq: 1<<40 + 8, Ack: 1<<39 + 9,
		WindowSize: 321, Data: []byte("v2-payload"),
	}
	wire := SealMAC(want, &key, 0)
	got, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMAC(got.Raw(), &key, 0); err != nil {
		t.Fatal(err)
	}
	if got.Magic != want.Magic || got.Version != want.Version || got.Cmd != want.Cmd ||
		got.Flags != want.Flags || got.SessionID != want.SessionID || got.PacketNo != want.PacketNo ||
		got.Seq != want.Seq || got.Ack != want.Ack || got.WindowSize != want.WindowSize ||
		!bytes.Equal(got.Data, want.Data) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestProtocolV2WireIsExactlyHeaderPayloadTag(t *testing.T) {
	rec := &Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1, Data: []byte("abc")}
	wire, err := rec.Marshal(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != RecordHdrSize+3+RecordTagSize {
		t.Fatalf("wire length = %d, want %d", len(wire), RecordHdrSize+3+RecordTagSize)
	}
	if binary.BigEndian.Uint16(wire[38:40]) != 3 {
		t.Fatalf("PayloadLen field = %d, want 3", binary.BigEndian.Uint16(wire[38:40]))
	}
}

func TestProtocolV2RejectsV1WithoutFallback(t *testing.T) {
	wire, _ := (&Record{Magic: MagicDefault, Version: Version, Cmd: CmdAck}).Marshal(0)
	wire[4] = 1
	if err := Parse(wire, MagicDefault, 0, new(Record)); err == nil {
		t.Fatal("protocol v1 record was accepted by the v2-only parser")
	}
}

func TestProtocolV2MACTamperMatrix(t *testing.T) {
	key := [32]byte{9, 8, 7, 6}
	wire := SealMAC(&Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdData,
		Flags: 3, SessionID: 11, PacketNo: 12, Seq: 13, Ack: 14,
		WindowSize: 15, Data: []byte("payload"),
	}, &key, 0)
	if err := VerifyMAC(wire, &key, 0); err != nil {
		t.Fatalf("valid record failed authentication: %v", err)
	}

	fields := map[string]int{
		"magic": 0, "version": 4, "command": 5, "flags": 6,
		"session": 8, "packet-number": 12, "sequence": 20,
		"ack": 28, "window": 36, "payload-length": 38,
		"payload": RecordHdrSize, "tag": len(wire) - 1,
	}
	for name, offset := range fields {
		t.Run(name, func(t *testing.T) {
			mutated := append([]byte(nil), wire...)
			mutated[offset] ^= 1
			if err := VerifyMAC(mutated, &key, 0); err == nil {
				t.Fatal("tampered record authenticated")
			}
		})
	}
}

func TestProtocolV2MagicMismatch(t *testing.T) {
	key := [32]byte{1}
	wire := SealMAC(&Record{Magic: MagicDefault, Version: Version, Cmd: CmdHandshakeSyn}, &key, 0)
	if err := Parse(wire, 0xDEADBEEF, 0, new(Record)); err == nil {
		t.Fatal("record with the wrong magic was accepted")
	}
	// ZeroMagic disables the check (the parser still validates the rest).
	if err := Parse(wire, ZeroMagic, 0, new(Record)); err != nil {
		t.Fatalf("ZeroMagic must skip the magic check: %v", err)
	}
}

func TestProtocolV2DirectionAndTranscriptKeySeparation(t *testing.T) {
	var clientNonce [ClientNonceSize]byte
	var serverNonce [ServerNonceSize]byte
	copy(clientNonce[:], "client-nonce-v2!")
	copy(serverNonce[:], "server-nonce-v2!")
	keys := DerivePSKSessionKeys("shared-secret", clientNonce, serverNonce, 7)
	if bytes.Equal(keys.C2S[:], keys.S2C[:]) {
		t.Fatal("client-to-server and server-to-client keys must differ")
	}

	clientKeys, err := keys.ClientFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := keys.ServerFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}

	// A record the client sealed must open server-side but never client-side:
	// the opposite-direction key cannot open a reflected record.
	rec := &Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdAck,
		SessionID: 7, PacketNo: 1, Ack: 3,
	}
	wire := SealRecordAEAD(rec, clientKeys.Send, nil, 0)
	parsed, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecordAEAD(parsed, serverKeys.Recv); err != nil {
		t.Fatalf("server could not open a client record: %v", err)
	}
	if _, err := OpenRecordAEAD(parsed, clientKeys.Recv); err == nil {
		t.Fatal("opposite-direction key opened a reflected record")
	}

	otherNonce := serverNonce
	otherNonce[0] ^= 1
	otherTranscript := DerivePSKSessionKeys("shared-secret", clientNonce, otherNonce, 7)
	otherSession := DerivePSKSessionKeys("shared-secret", clientNonce, serverNonce, 8)
	if bytes.Equal(keys.C2S[:], otherTranscript.C2S[:]) || bytes.Equal(keys.C2S[:], otherSession.C2S[:]) {
		t.Fatal("session key was not bound to both nonces and SessionID")
	}
}

func TestProtocolV2EveryControlRecordIsAuthenticated(t *testing.T) {
	key := [32]byte{4, 3, 2, 1}
	cipher, err := newNoiseCipherState(key[:])
	if err != nil {
		t.Fatal(err)
	}
	for i, cmd := range []uint8{CmdAck, CmdPing, CmdPong, CmdFin} {
		t.Run(commandName(cmd), func(t *testing.T) {
			wire := SealRecordAEAD(&Record{
				Magic: MagicDefault, Version: Version, Cmd: cmd,
				SessionID: 99, PacketNo: uint64(i + 1), Ack: 8,
			}, cipher, nil, 0)
			rec, err := ParseOwned(wire, MagicDefault, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !validSessionRecordShape(rec) {
				t.Fatal("valid control record rejected by shape gate")
			}
			plain, err := OpenRecordAEAD(rec, cipher)
			if err != nil || len(plain) != 0 {
				t.Fatalf("valid control record rejected: plain=%x err=%v", plain, err)
			}
			wire[len(wire)-1] ^= 1
			mutated, err := ParseOwned(wire, MagicDefault, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenRecordAEAD(mutated, cipher); err == nil {
				t.Fatal("tampered control-record tag opened")
			}
		})
	}
	for i, cmd := range []uint8{CmdPathChallenge, CmdPathResponse} {
		t.Run(commandName(cmd), func(t *testing.T) {
			token := bytes.Repeat([]byte{byte(i + 1)}, PathChallengeSize)
			wire := SealRecordAEAD(&Record{
				Magic: MagicDefault, Version: Version, Cmd: cmd,
				SessionID: 99, PacketNo: uint64(i + 10), Data: token,
			}, cipher, token, 0)
			rec, err := ParseOwned(wire, MagicDefault, 0)
			if err != nil || !validSessionRecordShape(rec) {
				t.Fatalf("path-control record rejected: %v", err)
			}
			plain, err := OpenRecordAEAD(rec, cipher)
			if err != nil || !bytes.Equal(plain, token) {
				t.Fatalf("path token = %x, err=%v", plain, err)
			}
		})
	}
	for _, n := range []int{0, PathChallengeSize - 1, PathChallengeSize + 1} {
		rec := &Record{
			Magic: MagicDefault, Version: Version,
			Cmd: CmdPathResponse, SessionID: 99, PacketNo: 20,
			Data: make([]byte, n),
		}
		if validSessionRecordShape(rec) {
			t.Fatalf("PATH_RESPONSE payload length %d passed the shape gate", n)
		}
	}
}

func TestProtocolV2SessionShapeRejectsZeroFields(t *testing.T) {
	if validSessionRecordShape(&Record{Cmd: CmdData, PacketNo: 1, Seq: 1}) {
		t.Fatal("DATA with zero SessionID passed the shape gate")
	}
	if validSessionRecordShape(&Record{Cmd: CmdData, SessionID: 1, Seq: 1}) {
		t.Fatal("DATA with zero PacketNo passed the shape gate")
	}
	if validSessionRecordShape(&Record{Cmd: CmdData, SessionID: 1, PacketNo: 1}) {
		t.Fatal("DATA with zero Seq passed the shape gate")
	}
	if validSessionRecordShape(&Record{Cmd: CmdAck, SessionID: 1, PacketNo: 1, Seq: 5}) {
		t.Fatal("ACK with non-zero Seq passed the shape gate")
	}
}

func TestProtocolV2NoiseControlRecordUsesHeaderAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	sender, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatal(err)
	}
	wire := SealRecordAEAD(&Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdFin,
		SessionID: 5, PacketNo: 1, Ack: 17,
	}, sender, nil, 0)
	rec, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenRecordAEAD(rec, receiver)
	if err != nil || len(plain) != 0 {
		t.Fatalf("valid encrypted control record failed: plaintext=%x err=%v", plain, err)
	}

	// Every header field is authenticated as AAD, so a mutation that stays
	// structurally parseable must still fail to open.
	for _, offset := range []int{6, 8, 12, 28, len(wire) - 1} {
		mutated := append([]byte(nil), wire...)
		mutated[offset] ^= 1
		bad, err := ParseOwned(mutated, MagicDefault, 0)
		if err != nil {
			t.Fatalf("mutation at %d should remain structurally parseable: %v", offset, err)
		}
		if _, err := OpenRecordAEAD(bad, receiver); err == nil {
			t.Fatalf("mutation at %d bypassed AEAD", offset)
		}
	}
}

// TestProtocolV2PSKOnlyPayloadIsConfidential proves PSK-only session records
// are ENCRYPTED, not just MAC'd: the payload must be unreadable on the wire
// and recoverable with the session keys.
func TestProtocolV2PSKOnlyPayloadIsConfidential(t *testing.T) {
	var clientNonce [ClientNonceSize]byte
	var serverNonce [ServerNonceSize]byte
	copy(clientNonce[:], "confidentiality-c!")
	copy(serverNonce[:], "confidentiality-s!")
	keys := DerivePSKSessionKeys("wire-psk", clientNonce, serverNonce, 42)
	clientKeys, err := keys.ClientFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := keys.ServerFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("PLAINTEXT-SECRET-do-not-ship: password=hunter2")
	wire := SealRecordAEAD(&Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdData,
		SessionID: 42, PacketNo: 1, Seq: 1,
	}, clientKeys.Send, secret, 0)
	if len(wire) == 0 {
		t.Fatal("failed to seal")
	}

	// The secret must not appear anywhere in header, payload, or tag.
	if bytes.Contains(wire, secret) {
		t.Fatal("sealed wire bytes contain the plaintext payload")
	}
	payload := wire[RecordHdrSize : len(wire)-RecordTagSize]
	if bytes.Contains(payload, []byte("hunter2")) {
		t.Fatal("payload field contains plaintext fragments")
	}

	// The peer recovers it; a wrong-direction key does not.
	parsed, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenRecordAEAD(parsed, serverKeys.Recv)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("server could not recover the payload: %q err=%v", plain, err)
	}
	if _, err := OpenRecordAEAD(parsed, clientKeys.Recv); err == nil {
		t.Fatal("client-direction key opened a server-bound record")
	}
}

func TestProtocolV2SizeLimits(t *testing.T) {
	if got := MaxPayloadFor(0); got != MaxPayloadLen {
		t.Fatalf("MaxPayloadFor(0) = %d, want %d", got, MaxPayloadLen)
	}
	if got := MaxPayloadFor(RecordHdrSize); got != 0 {
		t.Fatalf("MaxPayloadFor(%d) = %d, want 0", RecordHdrSize, got)
	}
	if got := MaxPayloadFor(RecordMinSize); got != 0 {
		t.Fatalf("MaxPayloadFor(%d) = %d, want 0", RecordMinSize, got)
	}
	if got := MaxPayloadFor(1450); got != 1450-RecordHdrSize-RecordTagSize {
		t.Fatalf("MaxPayloadFor(1450) = %d", got)
	}

	rec := &Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1, Data: make([]byte, 100)}
	if _, err := rec.Marshal(RecordHdrSize + 100 + RecordTagSize); err != nil {
		t.Fatalf("record exactly at the budget must marshal: %v", err)
	}
	if _, err := rec.Marshal(RecordHdrSize + 100 + RecordTagSize - 1); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversize record must fail with ErrRecordTooLarge, got %v", err)
	}
}

func TestProtocolV2ParseEnforcesCarrierLimit(t *testing.T) {
	key := [32]byte{1}
	wire := SealMAC(&Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1, Data: make([]byte, 200)}, &key, 0)
	if err := Parse(wire, MagicDefault, len(wire)-1, new(Record)); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("Parse must reject a record above the carrier limit, got %v", err)
	}
	if err := Parse(wire, MagicDefault, len(wire), new(Record)); err != nil {
		t.Fatalf("Parse must accept a record exactly at the carrier limit: %v", err)
	}
}

func TestProtocolV2PayloadLengthFieldMismatch(t *testing.T) {
	wire, _ := (&Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1, Data: []byte("abc")}).Marshal(0)
	binary.BigEndian.PutUint16(wire[38:40], 4) // claims 4, buffer holds 3
	if err := Parse(wire, MagicDefault, 0, new(Record)); err == nil {
		t.Fatal("record with a mismatched PayloadLen field was accepted")
	}
}

func TestProtocolV2TargetTLVRoundTrip(t *testing.T) {
	for _, target := range []string{"", "tcp://127.0.0.1:22", "udp://example.internal:53"} {
		field := TargetTLV(target)
		got, ok := parseTargetTLV(field)
		if target == "" {
			if ok {
				t.Fatal("empty target must encode to an absent TLV")
			}
			continue
		}
		if !ok || got != target {
			t.Fatalf("TLV round trip: got %q ok=%v, want %q", got, ok, target)
		}
	}
	if TargetTLV(string(make([]byte, TargetMaxLen+1))) != nil {
		t.Fatal("oversize target must not encode")
	}
}

func TestProtocolV2SplitSynPayload(t *testing.T) {
	var base [SynPayloadBase]byte
	copy(base[:ClientNonceSize], "0123456789abcdef")
	if _, _, err := splitSynPayload(base[:], false); err != nil {
		t.Fatalf("bare base SYN must split cleanly: %v", err)
	}

	withTarget := append(append([]byte(nil), base[:]...), TargetTLV("tcp://127.0.0.1:22")...)
	target, msg1, err := splitSynPayload(withTarget, false)
	if err != nil || target != "tcp://127.0.0.1:22" || msg1 != nil {
		t.Fatalf("target SYN split: target=%q msg1=%v err=%v", target, msg1, err)
	}

	msg := bytes.Repeat([]byte{0xAB}, NoiseMsg1Size)
	withNoise := append(append([]byte(nil), withTarget...), msg...)
	target, msg1, err = splitSynPayload(withNoise, true)
	if err != nil || target != "tcp://127.0.0.1:22" || !bytes.Equal(msg1, msg) {
		t.Fatalf("target+noise SYN split: target=%q msg1len=%d err=%v", target, len(msg1), err)
	}

	if _, _, err := splitSynPayload(base[:SynPayloadBase-1], false); err == nil {
		t.Fatal("short SYN payload must be rejected")
	}
}

func TestProtocolV2SplitAckPayload(t *testing.T) {
	var base [AckPayloadBase]byte
	copy(base[:ClientNonceSize], "0123456789abcdef")
	copy(base[ClientNonceSize:], "fedcba9876543210")
	granted, msg2, err := splitAckPayload(base[:], false)
	if err != nil || granted != "" || msg2 != nil {
		t.Fatalf("bare ACK split: granted=%q msg2=%v err=%v", granted, msg2, err)
	}
	withTarget := append(append([]byte(nil), base[:]...), TargetTLV("tcp://10.0.0.1:22")...)
	granted, _, err = splitAckPayload(withTarget, false)
	if err != nil || granted != "tcp://10.0.0.1:22" {
		t.Fatalf("granted target split: %q err=%v", granted, err)
	}
	if _, _, err := splitAckPayload(base[:AckPayloadBase-1], false); err == nil {
		t.Fatal("short ACK payload must be rejected")
	}
}

func TestParseTargetNetworkAndAddr(t *testing.T) {
	cases := []struct{ in, net, addr string }{
		{"tcp://127.0.0.1:22", "tcp", "127.0.0.1:22"},
		{"TCP://127.0.0.1:22", "tcp", "127.0.0.1:22"},
		{"udp://example.com:53", "udp", "example.com:53"},
		{"  udp://1.2.3.4:9  ", "udp", "1.2.3.4:9"},
		{"127.0.0.1:22", "tcp", "127.0.0.1:22"},
		{"", "tcp", ""},
	}
	for _, c := range cases {
		net, addr := ParseTargetNetworkAndAddr(c.in)
		if net != c.net || addr != c.addr {
			t.Fatalf("ParseTargetNetworkAndAddr(%q) = (%q,%q), want (%q,%q)", c.in, net, addr, c.net, c.addr)
		}
	}
}

func TestProtocolV2UnknownCommandRejected(t *testing.T) {
	wire, _ := (&Record{Magic: MagicDefault, Version: Version, Cmd: 0x7F}).Marshal(0)
	if err := Parse(wire, MagicDefault, 0, new(Record)); err == nil {
		t.Fatal("unknown command byte was accepted")
	}
}

func TestProtocolV2ParseBorrowsBufferParseOwnedCopies(t *testing.T) {
	key := [32]byte{1}
	wire := SealMAC(&Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: 1, PacketNo: 1, Seq: 1, Data: []byte("hello")}, &key, 0)

	var borrowed Record
	if err := Parse(wire, MagicDefault, 0, &borrowed); err != nil {
		t.Fatal(err)
	}
	// Mutating the backing buffer is visible through a borrowed parse...
	wire[RecordHdrSize] ^= 0xFF
	if borrowed.Data[0] != 'h'^0xFF {
		t.Fatal("Parse was expected to borrow the caller buffer")
	}

	owned, err := ParseOwned(wire, MagicDefault, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire[RecordHdrSize] ^= 0xFF // restore; owned copy must be unaffected
	if owned.Data[0] != 'h'^0xFF {
		t.Fatal("ParseOwned did not copy away from the caller buffer")
	}
}

func FuzzVerifyMACNeverPanics(f *testing.F) {
	key := [32]byte{1}
	f.Add([]byte{})
	f.Add(make([]byte, RecordMinSize))
	f.Fuzz(func(t *testing.T, wire []byte) {
		_ = VerifyMAC(wire, &key, 0)
	})
}

func FuzzParseNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, RecordMinSize))
	f.Fuzz(func(t *testing.T, wire []byte) {
		_ = Parse(wire, MagicDefault, 0, new(Record))
	})
}
