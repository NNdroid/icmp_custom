package tunnel

import "unsafe"

// Every 64-bit field in this package that is accessed with sync/atomic is
// declared as an atomic.Uint64. That type carries the compiler's align64
// guarantee: its fields are 8-byte aligned on EVERY GOARCH, including the
// 32-bit ones (arm, 386, mips) where a bare uint64 is only 4-byte aligned and
// any sync/atomic operation on it panics at runtime with panicUnaligned.
//
// These constant assertions turn that invariant into a build error on every
// platform: if one of the offsets below ever drifts off an 8-byte boundary,
// the array-size mismatch fails compilation.
var (
	// clientSession (client.go)
	_ = [0]byte([unsafe.Offsetof(clientSession{}.sendPacketNo) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(clientSession{}.sendSeq) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(clientSession{}.recvSeq) % 8]byte{})

	// ServerSession (server.go)
	_ = [0]byte([unsafe.Offsetof(ServerSession{}.sendPacketNo) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(ServerSession{}.sendSeq) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(ServerSession{}.recvSeq) % 8]byte{})

	// Server health counters (server.go)
	_ = [0]byte([unsafe.Offsetof(Server{}.decodeFailures) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(Server{}.macFailures) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(Server{}.replayDrops) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(Server{}.queueFullDrops) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(Server{}.sendFailures) % 8]byte{})
	_ = [0]byte([unsafe.Offsetof(Server{}.addrChanges) % 8]byte{})

	// eventBus (events.go)
	_ = [0]byte([unsafe.Offsetof(eventBus[SessionEvent]{}.dropped) % 8]byte{})
)
