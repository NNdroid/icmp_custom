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
			rf.window = [replayWindowBits / 64]uint64{}
		} else {
			for diff > 0 {
				step := diff
				if step > 64 {
					step = 64
				}
				for i := len(rf.window) - 1; i > 0; i-- {
					rf.window[i] = (rf.window[i] << step) | (rf.window[i-1] >> (64 - step))
				}
				rf.window[0] <<= step
				diff -= step
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
