package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameMessageRoundTrip(t *testing.T) {
	msg := []byte("hello framed world")
	enc, err := EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(enc) != uint32(len(msg)) {
		t.Fatalf("length prefix = %d, want %d", binary.BigEndian.Uint32(enc), len(msg))
	}
	asm := NewMessageAssembler(0)
	msgs, err := asm.Feed(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || !bytes.Equal(msgs[0], msg) {
		t.Fatalf("assembled %d messages: %q", len(msgs), msgs)
	}
	if asm.Pending() != 0 {
		t.Fatalf("pending = %d, want 0", asm.Pending())
	}
}

func TestFrameAssemblerAcrossChunks(t *testing.T) {
	enc, _ := EncodeMessage([]byte("split across three feeds"))
	asm := NewMessageAssembler(0)
	var got [][]byte
	for i := 0; i < len(enc); i += 3 {
		end := i + 3
		if end > len(enc) {
			end = len(enc)
		}
		msgs, err := asm.Feed(enc[i:end])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, msgs...)
	}
	if len(got) != 1 || string(got[0]) != "split across three feeds" {
		t.Fatalf("chunked reassembly failed: %q", got)
	}
}

func TestFrameAssemblerCoalescedMessages(t *testing.T) {
	enc, err := EncodeMessages([]byte("a"), []byte("bb"), []byte("ccc"))
	if err != nil {
		t.Fatal(err)
	}
	asm := NewMessageAssembler(0)
	msgs, err := asm.Feed(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 || string(msgs[0]) != "a" || string(msgs[1]) != "bb" || string(msgs[2]) != "ccc" {
		t.Fatalf("coalesced messages: %q", msgs)
	}
}

func TestFrameAssemblerPartialThenComplete(t *testing.T) {
	enc, _ := EncodeMessage([]byte("payload"))
	asm := NewMessageAssembler(0)
	msgs, err := asm.Feed(enc[:5])
	if err != nil || msgs != nil {
		t.Fatalf("partial feed: msgs=%q err=%v", msgs, err)
	}
	if asm.Pending() != 5 {
		t.Fatalf("pending = %d, want 5", asm.Pending())
	}
	msgs, err = asm.Feed(enc[5:])
	if err != nil || len(msgs) != 1 || string(msgs[0]) != "payload" {
		t.Fatalf("completion feed: msgs=%q err=%v", msgs, err)
	}
}

func TestFrameAssemblerOversizeBreaksStream(t *testing.T) {
	asm := NewMessageAssembler(16)
	var hdr [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:], 17) // one past the cap
	if _, err := asm.Feed(hdr[:]); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize length must fail with ErrMessageTooLarge, got %v", err)
	}
	if _, err := asm.Feed(nil); !errors.Is(err, ErrAssemblerBroken) {
		t.Fatalf("a broken assembler must keep returning ErrAssemblerBroken, got %v", err)
	}
	asm.Reset()
	if _, err := asm.Feed(nil); err != nil {
		t.Fatalf("Reset must clear the broken state: %v", err)
	}
}

func TestFrameEncodeMessageRejectsOversize(t *testing.T) {
	if _, err := EncodeMessage(make([]byte, MaxFramedMessage+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize EncodeMessage must fail, got %v", err)
	}
}

func TestFrameAssemblerDefaultLimit(t *testing.T) {
	asm := NewMessageAssembler(0)
	if asm.maxPayload != MaxFramedMessage {
		t.Fatalf("default maxPayload = %d, want %d", asm.maxPayload, MaxFramedMessage)
	}
}

// TestFrameAssemblerReclaimsBuffer checks the long-lived-stream bookkeeping:
// after consuming a large framed message the backing array must not keep
// growing unboundedly.
func TestFrameAssemblerReclaimsBuffer(t *testing.T) {
	asm := NewMessageAssembler(0)
	big := bytes.Repeat([]byte{0x5A}, 200*1024)
	enc, err := EncodeMessage(big)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asm.Feed(enc); err != nil {
		t.Fatal(err)
	}
	if cap(asm.buf) > 64*1024 {
		t.Fatalf("assembler retained a %d-byte backing array", cap(asm.buf))
	}
}

func TestFrameAssemblerOwnsMessagesAcrossFeeds(t *testing.T) {
	for _, split := range []int{0, 1, 4, 7} {
		t.Run(sizeName(split), func(t *testing.T) {
			frame, _ := EncodeMessages([]byte("first"), nil, []byte("third"))
			asm := NewMessageAssembler(0)
			got, err := asm.Feed(frame[:split])
			if err != nil {
				t.Fatal(err)
			}
			rest, err := asm.Feed(frame[split:])
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, rest...)
			clear(frame)
			next, _ := EncodeMessage([]byte("overwrite any retained buffer"))
			if _, err := asm.Feed(next); err != nil {
				t.Fatal(err)
			}
			if len(got) != 3 || string(got[0]) != "first" || len(got[1]) != 0 || string(got[2]) != "third" {
				t.Fatalf("messages changed after input reuse or next Feed: %q", got)
			}
			if asm.Pending() != 0 {
				t.Fatalf("Pending = %d, want 0", asm.Pending())
			}
		})
	}
}

func TestFrameAssemblerWideLengthRemainsPartial(t *testing.T) {
	// A uint32 header need not fit in int on 32-bit hosts. A header alone is
	// incomplete, never a complete frame with a wrapped (or negative) size.
	asm := NewMessageAssembler(^uint32(0))
	var header [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:], ^uint32(0))
	msgs, err := asm.Feed(header[:])
	if err != nil || len(msgs) != 0 || asm.Pending() != FrameHeaderSize {
		t.Fatalf("wide partial frame: msgs=%q err=%v pending=%d", msgs, err, asm.Pending())
	}
}

func FuzzMessageAssemblerChunking(f *testing.F) {
	f.Add([]byte("payload"), uint16(3))
	f.Add([]byte{}, uint16(1))
	f.Add([]byte("split header and coalesced frames"), uint16(7))
	f.Fuzz(func(t *testing.T, payload []byte, chunkSize uint16) {
		if len(payload) > 64<<10 {
			t.Skip()
		}
		want := [][]byte{payload, {}, []byte("tail")}
		wire, err := EncodeMessages(want...)
		if err != nil {
			t.Fatal(err)
		}
		asm := NewMessageAssembler(0)
		var got [][]byte
		step := 1 + int(chunkSize)
		for len(wire) > 0 {
			n := min(step, len(wire))
			msgs, err := asm.Feed(wire[:n])
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, msgs...)
			wire = wire[n:]
		}
		if len(got) != len(want) || asm.Pending() != 0 {
			t.Fatalf("got %d messages, pending %d", len(got), asm.Pending())
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("message %d differs", i)
			}
		}
	})
}
