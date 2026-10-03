package tunnel

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenRecordAEADIntoReusesCiphertext(t *testing.T) {
	cipher, err := newNoiseCipherState(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{nil, []byte("borrowed authenticated payload")} {
		wire := SealRecordAEAD(&Record{
			Magic: MagicDefault, Version: Version, Cmd: CmdData,
			SessionID: 1, PacketNo: 1, Seq: 1,
		}, cipher, payload, 0)
		header := append([]byte(nil), wire[:RecordHdrSize]...)
		var rec Record
		if err := Parse(wire, MagicDefault, 0, &rec); err != nil {
			t.Fatal(err)
		}
		plain, err := OpenRecordAEADInto(rec.Data[:0], &rec, cipher)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Fatalf("plaintext=%x err=%v", plain, err)
		}
		if len(plain) > 0 && &plain[0] != &wire[RecordHdrSize] {
			t.Fatal("in-place open allocated separate payload storage")
		}
		if !bytes.Equal(wire[:RecordHdrSize], header) {
			t.Fatal("in-place open modified the authenticated header")
		}
	}
}

func TestE2EReceiveBufferReuseAfterMissingFirstData(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()
	cEp, sEp, _ := newTestServer(t, ServerConfig{
		TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}, Logger: Nop{},
	}, nil)
	var dropped [2]atomic.Bool
	var reordered [2]atomic.Bool
	var firstReceived [2]atomic.Bool
	for i, ep := range []*fakeEndpoint{sEp, cEp} {
		ep.SetInboundFilter(func(packet fakePacket) bool {
			var rec Record
			if Parse(packet.data, MagicDefault, testRecordLimit, &rec) != nil || rec.Cmd != CmdData {
				return false
			}
			if rec.Seq == 1 && dropped[i].CompareAndSwap(false, true) {
				return true
			}
			if rec.Seq == 1 {
				firstReceived[i].Store(true)
			}
			if rec.Seq > 1 && !firstReceived[i].Load() {
				reordered[i].Store(true)
			}
			return false
		})
	}
	cli := newTestClient(t, ClientConfig{
		ServerAddr: "192.0.2.2", Passwords: []string{"secret"}, Logger: Nop{},
	}, cEp)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i*31) ^ byte(i>>8)
	}
	got := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, got)
		readDone <- err
	}()
	if err := writeAll(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reordered payload changed after receive buffer reuse")
	}
	for i := range dropped {
		if !dropped[i].Load() || !reordered[i].Load() {
			t.Fatalf("direction %d did not exercise a missing first DATA and later records", i)
		}
	}
}
