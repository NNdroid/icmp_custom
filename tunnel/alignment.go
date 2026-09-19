package tunnel

import "unsafe"

// This file is the 32-bit guard rail for the whole package.
//
// Every 64-bit field in this package that is touched with sync/atomic is
// declared as an atomic.Uint64 or atomic.Int64. Those types carry the
// compiler's align64 guarantee: on EVERY GOARCH, including the 32-bit ones
// (386, arm, mipsle, ...), the compiler places them on an 8-byte boundary.
// A bare uint64 is only 4-byte aligned there, and any sync/atomic operation
// on such a field panics at runtime with panicUnaligned.
//
// The assertions below make that type requirement a build error instead of a
// runtime surprise. Each one reads:
//
//	[int(unsafe.Alignof(x)) - 8]byte{}
//
// Alignof is 8 for atomic.Uint64 / atomic.Int64 and 4 for a bare uint64 on a
// 32-bit GOARCH, so the array length is zero when the field is typed
// correctly and -4 when it is not. A negative array length is a hard compile
// error: "invalid array length ... (constant -4 of type int)".
//
// Only Alignof is asserted, and deliberately so. The tempting addition is an
// Offsetof check too - "and the field must sit on an 8-byte boundary" - but
// it is subsumed: a field can only land at an offset that is not a multiple of
// 8 if its own alignment is 4 or less, which already makes the Alignof half
// fail. Asserting both would mean one half of every pair can never fire.
// Alignof == 8 is what forces the offset onto an 8-byte boundary in the first
// place, so it is the only half that carries information.
//
// The Alignof half is only meaningful on 32-bit GOARCHes: on a 64-bit target a
// bare uint64 is already 8-byte aligned, so the assertion is a no-op there. CI
// must therefore cross-build 386, arm and mipsle (see
// .github/workflows/ci.yml) - without that step this file protects nothing.
//
// sync.WaitGroup needs no entry here. Its Alignof is 8 because of the
// atomic.Uint64 it embeds, so the compiler pads around every WaitGroup value
// and its internal counter is always on an 8-byte boundary. Adding a uint32
// before a WaitGroup adds padding rather than shifting it.
//
// There is no helper function for these checks. unsafe.Alignof must see the
// struct literal directly, and routing the checks through a generic function
// would pass the atomic value by value - which vet's copylock rejects with
// "variable declaration copies lock value to _".

var (
	// clientSession (client.go)
	_ = [int(unsafe.Alignof(clientSession{}.sendPacketNo)) - 8]byte{}
	_ = [int(unsafe.Alignof(clientSession{}.sendSeq)) - 8]byte{}
	_ = [int(unsafe.Alignof(clientSession{}.recvSeq)) - 8]byte{}

	// ServerSession (server.go)
	_ = [int(unsafe.Alignof(ServerSession{}.sendPacketNo)) - 8]byte{}
	_ = [int(unsafe.Alignof(ServerSession{}.sendSeq)) - 8]byte{}
	_ = [int(unsafe.Alignof(ServerSession{}.recvSeq)) - 8]byte{}

	// Server health counters (server.go)
	_ = [int(unsafe.Alignof(Server{}.decodeFailures)) - 8]byte{}
	_ = [int(unsafe.Alignof(Server{}.macFailures)) - 8]byte{}
	_ = [int(unsafe.Alignof(Server{}.replayDrops)) - 8]byte{}
	_ = [int(unsafe.Alignof(Server{}.queueFullDrops)) - 8]byte{}
	_ = [int(unsafe.Alignof(Server{}.sendFailures)) - 8]byte{}
	_ = [int(unsafe.Alignof(Server{}.addrChanges)) - 8]byte{}

	// eventBus (events.go)
	_ = [int(unsafe.Alignof(eventBus[SessionEvent]{}.dropped)) - 8]byte{}

	// icmpCore (icmpprofile.go): the polling counters and the frag-needed
	// adoption timestamp. icmpCore was the struct the first revision of this
	// file forgot, which is how it grew three 64-bit atomic fields with no
	// assertion covering any of them.
	_ = [int(unsafe.Alignof(icmpCore{}.pollsSent)) - 8]byte{}
	_ = [int(unsafe.Alignof(icmpCore{}.repliesSeen)) - 8]byte{}
	_ = [int(unsafe.Alignof(icmpCore{}.lastFragAdopt)) - 8]byte{}
)

// Keep this file in step with every new 64-bit atomic field added to the
// package. Forgetting is not fatal: atomic.Uint64 self-aligns, so an
// unasserted field is still safe to use. It is safe without proof, which is
// how icmpCore's three fields sat uncovered.
