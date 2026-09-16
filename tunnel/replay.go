package tunnel

import "sync"

// replayWindowBits is the width of the per-direction replay window, in packets.
// 2048 bits = 32 uint64 words. The window is the same for both directions and
// for every carrier: the record layer is transport independent.
const replayWindowBits = 2048

// ReplayFilter implements the per-direction 2048-packet sliding window used by
// every established v2 record. Packet number zero and packets older than the
// window are always rejected. There is deliberately no wrap-around: exhausting
// uint64 packet numbers closes the session before another nonce can be used.
//
// The filter is safe for concurrent use; a session drives it from its single
// receive path but the ARQ layer may reach it from a timer goroutine too.
type ReplayFilter struct {
	maxSeq  uint64
	seenMax bool
	window  [replayWindowBits / 64]uint64
	mu      sync.Mutex
}

// Seen reports whether seq has already been accepted, without changing state.
// It is a read-only peek; use Accept to actually claim a packet number.
func (rf *ReplayFilter) Seen(seq uint64) bool {
	if seq == 0 {
		return true
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if !rf.seenMax {
		return false
	}
	if seq > rf.maxSeq {
		return false
	}
	behind := rf.maxSeq - seq
	if behind >= replayWindowBits {
		return true
	}
	return (rf.window[behind/64] & (1 << (behind % 64))) != 0
}

// acceptLocked claims seq. The caller must hold rf.mu.
func (rf *ReplayFilter) acceptLocked(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if !rf.seenMax {
		rf.seenMax = true
		rf.maxSeq = seq
		rf.window[0] = 1
		return true
	}
	if seq > rf.maxSeq {
		diff := seq - rf.maxSeq
		if diff >= replayWindowBits {
			// The whole window fell behind: reset and accept the new head.
			rf.window = [replayWindowBits / 64]uint64{}
		} else {
			wordShift := diff / 64
			bitShift := diff % 64
			if wordShift > 0 {
				// Advance whole words: high words fall out of the window and
				// the low words become zero.
				ws := int(wordShift)
				copy(rf.window[ws:], rf.window[:len(rf.window)-ws])
				for i := 0; i < ws; i++ {
					rf.window[i] = 0
				}
			}
			if bitShift > 0 {
				// Bit-level shift with carry from the word below, iterating
				// LOW word to HIGH so a word is read before the carry it
				// supplies to the next word is consumed. A non-constant shift
				// count in Go is taken modulo the operand width, so we keep
				// bitShift strictly below 64 (never shift by 64, which would
				// otherwise be a no-op and corrupt the window).
				var carry uint64
				for i := 0; i < len(rf.window); i++ {
					top := rf.window[i] >> (64 - bitShift)
					rf.window[i] = (rf.window[i] << bitShift) | carry
					carry = top
				}
			}
		}
		rf.maxSeq = seq
		rf.window[0] |= 1
		return true
	}
	behind := rf.maxSeq - seq
	if behind >= replayWindowBits {
		return false
	}
	wordIdx := behind / 64
	bitIdx := behind % 64
	if (rf.window[wordIdx] & (1 << bitIdx)) != 0 {
		return false
	}
	rf.window[wordIdx] |= 1 << bitIdx
	return true
}

// Accept claims seq, returning true the first time and false for a replay or a
// packet older than the window.
func (rf *ReplayFilter) Accept(seq uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.acceptLocked(seq)
}

// Remove rolls back a just-accepted packet when a bounded receive queue could
// not retain it. This lets an exact retransmission be considered again.
func (rf *ReplayFilter) Remove(seq uint64) {
	if seq == 0 {
		return
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if !rf.seenMax || seq > rf.maxSeq || rf.maxSeq-seq >= replayWindowBits {
		return
	}
	behind := rf.maxSeq - seq
	rf.window[behind/64] &^= 1 << (behind % 64)
}

// CheckAndAdd returns true for a replay/too-old packet, false for a newly
// accepted packet.
func (rf *ReplayFilter) CheckAndAdd(seq uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return !rf.acceptLocked(seq)
}
