package tunnel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxWireRecordSize bounds a read buffer when the carrier declares no budget.
// It is the largest record the uint16 PayloadLen field can describe.
const maxWireRecordSize = RecordHdrSize + MaxPayloadLen + RecordTagSize

// ServerConfig configures a Server.
//
// Note what is NOT here: the UDP profile's `port_range` / `origdst` /
// `sendsock_max` / `receive_sockets` — and `listen`, because ICMP binds no
// port. `encoding/json` ignores unknown keys, so a config file carrying them is
// accepted without being read (see DESIGN_ICMP.md §0).
type ServerConfig struct {
	// Transport names the carrier. Only "icmp" exists in this project; an
	// empty value selects it. Any other value is rejected at construction
	// time by NewServer, before a socket is opened.
	Transport string `json:"transport"`
	// ICMP is the ICMP carrier profile. Its zero value is exactly the
	// documented default profile, so an omitted `icmp` object means
	// "defaults". It is read by NewServer, not by NewServerWithTransport,
	// which already has a carrier.
	ICMP ICMPProfile `json:"icmp"`
	// TargetAddr is the default forwarding endpoint, e.g. "tcp://127.0.0.1:22"
	// or "udp://10.0.0.5:51820". An endpoint without a scheme is TCP.
	TargetAddr string `json:"target"`
	// Passwords are the accepted PSKs. At least one non-blank is mandatory:
	// there is no open/unauthenticated mode.
	Passwords []string `json:"passwords"`
	// Magic overrides the record magic. Zero selects MagicDefault; a configured
	// magic must never be zero (zero is the "skip the check" sentinel).
	Magic uint32 `json:"magic"`
	// PrivateKey enables Noise_NK when non-empty (32-byte Curve25519 key as hex
	// or base64). Without it the session is PSK-only: still confidential, but
	// without forward secrecy.
	PrivateKey string `json:"privkey"`
	// AllowedTargets gates client-REQUESTED forwarding endpoints. Patterns
	// support '*' (any sequence) and '?' (one character) in the host and the
	// port; the network must match exactly. An empty list means only the
	// default TargetAddr is reachable — every client request is silently
	// denied, exactly like any other handshake failure.
	//
	// To use the handshake-time MTU probe (mtu_mode "probe"), allow
	// "discard://*" here; see DESIGN_ICMP.md §4.8 option A'.
	AllowedTargets []string `json:"allowed_targets"`
	// SendWindow caps DATA records awaiting ACK before the target read loop
	// blocks (0 = 256). It bounds both the unacked map and the retransmit
	// backlog for a stalled client.
	SendWindow int `json:"send_window"`
	// LogLevel is debug|info|warn|error. Ignored when Logger is set.
	LogLevel string `json:"log_level"`
	// Logger receives diagnostics. An injected Logger wins over LogLevel and
	// is never nil-checked afterwards (pass Nop for silence).
	Logger Logger `json:"-"`
}

// defaultSendWindow is the cap on records awaiting ACK before the target read
// loop blocks. 256 records x ~1.2KB is roughly 300KB in flight, which bounds
// both the unacked map and the retransmit backlog for a stalled client.
const defaultSendWindow = 256

const (
	pathChallengeTTL  = 5 * time.Second
	maxPathChallenges = 8

	// serverIdleTimeout is how long a session with no authenticated traffic is
	// kept before the cleanup loop reaps it.
	serverIdleTimeout = 60 * time.Second
	cleanupInterval   = 15 * time.Second
)

// synCacheTTL is how long a verified handshake nonce is remembered. It must
// exceed the +-300s timestamp acceptance window so a replayed SYN can never be
// re-verified after its cache entry expires.
const synCacheTTL = 10 * time.Minute

// synCacheMax caps the handshake idempotency cache.
const synCacheMax = 4096

type pathChallenge struct {
	token   [PathChallengeSize]byte
	expires time.Time
}

// Server terminates tunnels and forwards each session to its backend target.
//
// The carrier is injected: the same session layer runs over the raw ICMP
// transport, the Android ping-socket transport, or an in-memory fake. The
// server never touches sockets itself.
type Server struct {
	cfg      ServerConfig
	tr       Transport
	logger   Logger
	dialFunc TargetDialer

	maxRecordSize int
	maxPayload    int

	// mtuFed and authFed are the carrier's optional feedback capabilities,
	// resolved once at construction (the carrier is immutable) so the per-record
	// paths never re-assert an interface. Both are nil for an ordinary carrier,
	// which is nearly all of them, and every use is nil-checked.
	mtuFed  MTUFeedback
	authFed AuthenticatedFeedback

	privKey    [32]byte
	hasPrivKey bool

	sessions  sync.Map // uint32 -> *ServerSession
	closed    int32
	closeChan chan struct{}
	wg        sync.WaitGroup

	events *eventBus[SessionEvent]

	// synCache remembers verified handshake nonces so a retransmitted/replayed
	// SYN gets the SAME ack resent (idempotent) instead of dialing the target
	// again. This kills both the replay-amplification and the
	// duplicate-target-connection problems at once.
	synCache *synCache
	// synLimiter rate-limits SYNs per source IP; handshakeSem caps the number
	// of concurrent (potentially slow) target dials.
	synLimiter   *synLimiter
	handshakeSem chan struct{}

	sendWindow   int
	maxRecvQueue int

	// Counters (read with atomic; used for logging and Stats).
	decodeFailures uint64 // undecodable records (junk, scans, mismatched peers)
	macFailures    uint64 // v2 authentication failures
	replayDrops    uint64 // authenticated records rejected by the replay window
	queueFullDrops uint64 // reorder-buffer overflows
	sendFailures   uint64 // carrier write failures
	addrChanges    uint64 // times a session's observed peer address changed
}

// NewServerWithTransport builds a server on an injected carrier. It is the
// injection seam used by tests (in-memory fake), by embedders that own the
// carrier, and by the profile-default constructors.
//
// A nil dialer falls back to a plain net.Dial against the granted target.
func NewServerWithTransport(cfg ServerConfig, tr Transport, dial TargetDialer) (*Server, error) {
	if tr == nil {
		return nil, errors.New("server: transport is required")
	}
	passwords := make([]string, 0, len(cfg.Passwords))
	for _, password := range cfg.Passwords {
		if password = strings.TrimSpace(password); password != "" {
			passwords = append(passwords, password)
		}
	}
	if len(passwords) == 0 {
		return nil, fmt.Errorf("%w: server requires at least one password (PSK)", ErrConfigRequired)
	}
	cfg.Passwords = passwords
	if cfg.Magic == 0 {
		cfg.Magic = MagicDefault
	}
	logger := resolveLogger(cfg.Logger, cfg.LogLevel)

	if dial == nil {
		dial = defaultTargetDialer()
	}
	srv := &Server{
		cfg:      cfg,
		tr:       tr,
		logger:   logger,
		dialFunc: dial,
		// The record ceiling is the RECEIVE ceiling, not the carrier's live
		// send budget: it must cover whatever the peer may legitimately send,
		// so it is sized once from the fixed value and used for the read
		// buffer, for Parse and for the seal limit.
		maxRecordSize: maxReceiveSizeOf(tr),
		maxPayload:    MaxPayloadFor(maxReceiveSizeOf(tr)),
		mtuFed:        mtuFeedbackOf(tr),
		authFed:       authenticatedFeedbackOf(tr),
		closeChan:     make(chan struct{}),
		events:        newEventBus[SessionEvent](256),
		synCache:      newSynCache(),
		synLimiter:    newSynLimiter(5, 20),
		handshakeSem:  make(chan struct{}, 64),
		sendWindow:    defaultSendWindow,
		maxRecvQueue:  512,
	}
	if cfg.SendWindow > 0 {
		srv.sendWindow = cfg.SendWindow
	}
	if cfg.PrivateKey != "" {
		pk, err := ParseNoiseKey(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid noise private key: %w", err)
		}
		srv.privKey = pk
		srv.hasPrivKey = true
		logger.Infof("[Server] Noise_NK enabled (forward secrecy)")
	}
	for _, p := range cfg.AllowedTargets {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		_, rest := ParseTargetNetworkAndAddr(p)
		if _, _, err := net.SplitHostPort(rest); err != nil && !strings.ContainsAny(rest, "*?") {
			logger.Warnf("[Server] allowed_targets pattern %q looks malformed (no port and no wildcard) and will never match", p)
		}
	}
	return srv, nil
}

// sendPayloadBudget is the largest DATA payload the carrier can carry RIGHT
// NOW. It is re-read per use rather than cached, which is the whole point: an
// adaptive carrier (the ICMP profile's automatic MTU) narrows and widens this
// without the session containing a single line about MTUs.
func (s *Server) sendPayloadBudget() int {
	return payloadBudgetOf(s.tr, s.maxPayload)
}

// Start runs the receive loop and blocks until Close. The carrier must already
// be open; Start only drives it.
func (s *Server) Start() error {
	netType, target := ParseTargetNetworkAndAddr(s.cfg.TargetAddr)
	s.logInfo("[Server] target [%s] %s record_budget=%d max_payload=%d peers=%s",
		netType, target, s.maxRecordSize, s.maxPayload, s.tr.RemoteID())
	s.logInfo("[Server] protocol v2 authentication enabled with %d PSK(s)", len(s.cfg.Passwords))

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.readLoop()
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupLoop()
	}()

	<-s.closeChan
	s.wg.Wait()
	return nil
}

// readLoop is the single receive path. The carrier guarantees one reader.
func (s *Server) readLoop() {
	bufSize := s.maxRecordSize
	if bufSize <= 0 {
		bufSize = maxWireRecordSize
	}
	buf := make([]byte, bufSize)
	for {
		if atomic.LoadInt32(&s.closed) == 1 {
			return
		}
		n, path, err := s.tr.ReadRecord(buf)
		if err != nil {
			if atomic.LoadInt32(&s.closed) == 1 || isClosedTransportErr(err) {
				return
			}
			s.logWarn("[Server] carrier read error: %v", err)
			return
		}
		var rec Record
		if err := Parse(buf[:n], s.cfg.Magic, s.maxRecordSize, &rec); err != nil {
			if c := atomic.AddUint64(&s.decodeFailures, 1); c == 1 || c%1000 == 0 {
				s.logWarn("[Server] undecodable record from %s (%d bytes): %v (count=%d)", path.Peer, n, err, c)
			}
			continue
		}
		if s.loggerLevel() <= LogLevelDebug {
			s.logDebug("[Recv] peer=%s ident=%d seq=%d cmd=0x%02X sid=0x%08X len=%d",
				path.Peer, path.Ident, path.Seq, rec.Cmd, rec.SessionID, n)
		}

		if rec.Cmd == CmdHandshakeSyn {
			// Cheap DoS gates before anything expensive: per-IP rate limit,
			// then the (verifying) handshake goroutine.
			if ip := ipOf(path.Peer); !s.synLimiter.Allow(ip, time.Now()) {
				s.logWarn("[Handshake] rate-limited SYN from %s", path.Peer)
				continue
			}
			if rec.SessionID != 0 || rec.PacketNo != 0 || rec.Seq != 0 || rec.Ack != 0 || len(rec.Data) < SynPayloadBase {
				continue
			}
			var clientNonce [ClientNonceSize]byte
			copy(clientNonce[:], rec.Data[:ClientNonceSize])
			matchedPSK := matchSynPSK(rec.Raw(), s.cfg.Passwords, clientNonce)
			if matchedPSK == "" {
				s.logWarn("[Handshake] rejected SYN from %s: record MAC verification failed", path.Peer)
				continue
			}
			// The read buffer is reused while verification runs asynchronously,
			// so retain this record.
			owned, err := ParseOwned(buf[:n], s.cfg.Magic, s.maxRecordSize)
			if err != nil {
				continue
			}
			go s.handleHandshake(path, owned, matchedPSK)
			continue
		}

		// Dispatch to an existing session. The inner v2 SessionID is the only
		// authoritative session key; the carrier's Ident is a cheap prefilter.
		if v, ok := s.sessions.Load(rec.SessionID); ok && v != nil {
			v.(*ServerSession).processIncomingRecord(&rec, path)
		}
	}
}

// handleHandshake verifies a SYN and establishes a session.
func (s *Server) handleHandshake(path PathID, rec *Record, matchedPSK string) {
	// SYN payload: [16B ClientNonce] [8B Timestamp] [target TLV] [optional 48B
	// Noise msg1]. The base payload is mandatory; the target request and msg1
	// are optional and validated against what this server actually runs.
	expectedLen := SynPayloadBase
	if s.hasPrivKey {
		expectedLen += NoiseMsg1Size
	}
	if matchedPSK == "" || len(rec.Data) < expectedLen || len(rec.Data) > SynPayloadBase+TargetTLVLen+TargetMaxLen+NoiseMsg1Size {
		s.logWarn("[Handshake] rejected SYN from %s: invalid payload length %d", path.Peer, len(rec.Data))
		return
	}

	var clientNonce [ClientNonceSize]byte
	copy(clientNonce[:], rec.Data[:ClientNonceSize])
	timestamp := int64(binary.BigEndian.Uint64(rec.Data[ClientNonceSize:SynPayloadBase]))

	// Reject stale/future SYNs: +-300s tolerates clock skew without leaving a
	// replay window open for long.
	now := time.Now().Unix()
	if timestamp < now-300 || timestamp > now+300 {
		s.logWarn("[Handshake] rejected SYN from %s: expired timestamp (%d vs now %d)", path.Peer, timestamp, now)
		return
	}

	requestedTarget, noiseMsg1, err := splitSynPayload(rec.Data, s.hasPrivKey)
	if err != nil {
		s.logWarn("[Handshake] rejected SYN from %s: %v", path.Peer, err)
		return
	}
	if len(rec.Data) != SynPayloadBase+len(TargetTLV(requestedTarget))+len(noiseMsg1) {
		s.logWarn("[Handshake] rejected SYN from %s: trailing bytes in payload", path.Peer)
		return
	}
	if requestedTarget != "" && !targetAllowed(requestedTarget, s.cfg.AllowedTargets) {
		reqNet, reqAddr := ParseTargetNetworkAndAddr(requestedTarget)
		s.logWarn("[Handshake] rejected SYN from %s: requested target %q is not in allowed_targets", path.Peer, requestedTarget)
		s.emitSessionEvent(SessionEvent{
			Kind:    SessionTargetDenied,
			Remote:  path.Peer,
			Network: reqNet,
			Address: reqAddr,
			Detail:  requestedTarget,
		})
		return
	}

	handshakeKeys := DerivePSKHandshakeKeys(matchedPSK, clientNonce)
	cacheKey := makeSynCacheKey(clientNonce, handshakeKeys.SynMAC)

	// Idempotent replay handling: a verified nonce we have seen before gets the
	// same ACK resent — no new session, no second target dial. This covers the
	// legitimate case (client lost our ACK and retransmits the SYN) and kills
	// the replay case (a captive SYN within the +-300s window can no longer
	// force a fresh target connection per replay).
	cached, owner := s.synCache.Acquire(cacheKey, time.Now())
	if cached != nil {
		s.logInfo("[Handshake] replayed SYN from %s: resending cached ACK", path.Peer)
		_ = s.tr.ReplyRecord(cached, path)
		return
	}
	if !owner {
		// Another goroutine is already establishing this exact nonce. Its ACK
		// will be cached shortly; a normal client retransmission will get it.
		return
	}
	handshakeComplete := false
	defer func() {
		if !handshakeComplete {
			s.synCache.Abort(cacheKey)
		}
	}()

	// Cap concurrent handshakes: the target dial below can block for seconds,
	// so unbounded SYN intake would pile up goroutines and sockets.
	select {
	case s.handshakeSem <- struct{}{}:
		defer func() { <-s.handshakeSem }()
	case <-s.closeChan:
		return
	case <-time.After(2 * time.Second):
		s.logWarn("[Handshake] backlog full, dropping SYN from %s", path.Peer)
		return
	}

	var noiseSess *NoiseSession
	var noiseMsg2 []byte
	if s.hasPrivKey {
		var err error
		noiseSess, noiseMsg2, err = NewServerNoiseSession(s.privKey, noiseMsg1)
		if err != nil {
			s.logWarn("[Handshake] Noise_NK handshake failed: %v", err)
			return
		}
		s.logInfo("[Handshake] Noise_NK complete for %s (channel binding %x...)", path.Peer, noiseSess.HandshakeHash[:4])
	}

	// Forwarding endpoint: the client's allowed request, else the default.
	targetAddr := s.cfg.TargetAddr
	if requestedTarget != "" {
		targetAddr = requestedTarget
	}
	targetNet, targetHostPort := ParseTargetNetworkAndAddr(targetAddr)

	// Allocate a unique SessionID BEFORE dialing: a custom dialer is keyed by
	// session, so embedders can route/annotate per tunnel.
	sid, err := s.allocateSessionID()
	if err != nil {
		s.logError("[Handshake] crypto/rand failed: %v", err)
		return
	}

	var upstream net.Conn
	if isDiscardNetwork(targetNet) {
		// The built-in sink is not a dial at all: it is created in-process, so
		// it behaves identically with an injected dialer, a test stub, or none.
		// It backs the ICMP profile's active MTU probe (see discard.go).
		upstream = newDiscardSink()
		s.logInfo("[Session 0x%08X] target is the built-in discard sink", sid)
	} else {
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelDial()
		var dialErr error
		upstream, dialErr = s.dialFunc(dialCtx, sid, targetNet, targetHostPort)
		if dialErr != nil {
			s.logError("[Handshake] failed to dial target [%s] %s: %v", targetNet, targetHostPort, dialErr)
			return
		}
	}

	var serverNonce [ServerNonceSize]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		s.logError("[Handshake] crypto/rand failed: %v", err)
		_ = upstream.Close()
		return
	}

	// Record protection: Noise traffic uses the forward-secret transport keys;
	// PSK-only traffic uses AEAD keys derived from the PSK + both nonces + SID
	// (same wire format, but no forward secrecy).
	var frameKeys *FrameKeys
	if noiseSess != nil {
		frameKeys = &FrameKeys{Send: noiseSess.SendCipher, Recv: noiseSess.RecvCipher}
	} else {
		keys := DerivePSKSessionKeys(matchedPSK, clientNonce, serverNonce, sid)
		if frameKeys, err = keys.ServerFrameCiphers(); err != nil {
			s.logError("[Handshake] session cipher init failed: %v", err)
			_ = upstream.Close()
			return
		}
	}

	sess := &ServerSession{
		server:        s,
		sessionID:     sid,
		raddr:         path.Peer,
		pathID:        path,
		pathValid:     true, // the handshake itself proved this path works
		targetNetwork: targetNet,
		targetAddr:    targetHostPort,
		upstream:      upstream,
		frameKeys:     frameKeys,
		sendSeq:       1,
		recvSeq:       1,
		recvQueue:     make(map[uint64][]byte),
		unacked:       make(map[uint64]*unackedPkt),
		lastActive:    time.Now(),
		closeChan:     make(chan struct{}),
		rttEst:        newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	s.sessions.Store(sid, sess)

	// ACK payload echoes ClientNonce for concurrent-handshake routing and adds
	// ServerNonce for session key freshness, then the granted target (when the
	// client requested one) and the optional Noise msg2.
	ackData := make([]byte, 0, AckPayloadBase+TargetTLVLen+len(requestedTarget)+len(noiseMsg2))
	ackData = append(ackData, clientNonce[:]...)
	ackData = append(ackData, serverNonce[:]...)
	ackData = appendTargetTLV(ackData, requestedTarget)
	ackData = append(ackData, noiseMsg2...)
	ackFrame := &Record{
		Magic:      s.cfg.Magic,
		Version:    Version,
		Cmd:        CmdHandshakeAck,
		SessionID:  sid,
		WindowSize: 65535,
		Data:       ackData,
	}
	ackEncoded := SealMAC(ackFrame, &handshakeKeys.AckMAC, s.maxRecordSize)
	if len(ackEncoded) == 0 {
		s.logError("[Handshake] failed to seal ACK for session 0x%08X", sid)
		s.sessions.Delete(sid)
		sess.Close()
		return
	}
	s.synCache.Complete(cacheKey, ackEncoded)
	handshakeComplete = true
	_ = s.tr.ReplyRecord(ackEncoded, path)

	s.logInfo("[Session 0x%08X] established for %s -> target [%s] %s", sid, path.Peer, targetNet, targetHostPort)
	if requestedTarget != "" {
		s.logInfo("[Session 0x%08X] client-requested target honored: %s", sid, requestedTarget)
	}
	s.emitSessionEvent(SessionEvent{
		Kind:      SessionEstablished,
		SessionID: sid,
		Remote:    path.Peer,
		Network:   targetNet,
		Address:   targetHostPort,
		Detail:    requestedTarget,
	})

	go sess.upstreamLoop()
	go sess.retransmitLoop()
}

// allocateSessionID draws a non-zero SessionID not currently in use.
func (s *Server) allocateSessionID() (uint32, error) {
	var sidBuf [4]byte
	for {
		if _, err := rand.Read(sidBuf[:]); err != nil {
			return 0, err
		}
		sid := binary.BigEndian.Uint32(sidBuf[:])
		if sid == 0 {
			continue
		}
		if _, exists := s.sessions.Load(sid); !exists {
			return sid, nil
		}
	}
}

// Close stops the server: it closes the carrier, tears down every session and
// stops the event bus. Safe to call more than once.
func (s *Server) Close() {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		close(s.closeChan)
		_ = s.tr.Close()
		s.sessions.Range(func(_, value any) bool {
			value.(*ServerSession).Close()
			return true
		})
		s.events.close()
	}
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(_, value any) bool {
				sess := value.(*ServerSession)
				sess.activeMu.Lock()
				inactive := now.Sub(sess.lastActive)
				sess.activeMu.Unlock()
				if inactive > serverIdleTimeout {
					s.logInfo("[Session 0x%08X] inactive for %v, cleaning up", sess.sessionID, inactive)
					sess.Close()
				}
				return true
			})
			s.logDebug("[Stats] sessions=%d authFail=%d replayDrop=%d queueFull=%d decodeFail=%d sendFail=%d addrChange=%d",
				s.sessionCount(),
				atomic.LoadUint64(&s.macFailures),
				atomic.LoadUint64(&s.replayDrops),
				atomic.LoadUint64(&s.queueFullDrops),
				atomic.LoadUint64(&s.decodeFailures),
				atomic.LoadUint64(&s.sendFailures),
				atomic.LoadUint64(&s.addrChanges))
		}
	}
}

func (s *Server) sessionCount() int {
	n := 0
	s.sessions.Range(func(_, _ any) bool { n++; return true })
	return n
}

// ServerStats is a point-in-time snapshot of the server's health counters.
// All counters are cumulative since start; Sessions is a live gauge.
type ServerStats struct {
	Sessions       int    // live sessions (gauge)
	AuthFailures   uint64 // v2 authentication rejections (forgery/replay diagnostics)
	DecodeFailures uint64 // undecodable records (junk, scans, mismatched peers)
	ReplayDrops    uint64 // authenticated records rejected by the replay window
	QueueFullDrops uint64 // reorder-buffer overflows (client behind or loss)
	SendFailures   uint64 // carrier write failures
	AddressChanges uint64 // observed peer-address changes (NAT rebinding/migration)
}

// Stats returns a snapshot of the counters the server also logs periodically.
func (s *Server) Stats() ServerStats {
	return ServerStats{
		Sessions:       s.sessionCount(),
		AuthFailures:   atomic.LoadUint64(&s.macFailures),
		DecodeFailures: atomic.LoadUint64(&s.decodeFailures),
		ReplayDrops:    atomic.LoadUint64(&s.replayDrops),
		QueueFullDrops: atomic.LoadUint64(&s.queueFullDrops),
		SendFailures:   atomic.LoadUint64(&s.sendFailures),
		AddressChanges: atomic.LoadUint64(&s.addrChanges),
	}
}

func (s *Server) logDebug(format string, v ...any) { s.logger.Debugf(format, v...) }
func (s *Server) logInfo(format string, v ...any)  { s.logger.Infof(format, v...) }
func (s *Server) logWarn(format string, v ...any)  { s.logger.Warnf(format, v...) }
func (s *Server) logError(format string, v ...any) { s.logger.Errorf(format, v...) }

// loggerLevel reports the configured verbosity for debug-gating hot paths. An
// injected Logger always receives everything (level 0); the filter lives
// inside resolveLogger for the default std logger.
func (s *Server) loggerLevel() int {
	if s.cfg.Logger != nil {
		return LogLevelDebug
	}
	return LogLevel(s.cfg.LogLevel)
}

// SessionEventKind enumerates the lifecycle transitions reported through
// Server.SetEventHandler.
type SessionEventKind int

const (
	// SessionEstablished fires after the handshake completed, the target
	// passed the filter, the backend was dialed, and the session is live.
	SessionEstablished SessionEventKind = iota
	// SessionClosed fires exactly once when the session tears down (FIN,
	// idle timeout, max retries, backend error, or server Close).
	SessionClosed
	// SessionAuthRejected fires when a session-bound record fails AEAD
	// verification — the security-event hook for SIEM pipelines.
	SessionAuthRejected
	// SessionReplayDropped fires when an authenticated record is rejected by
	// the per-direction replay window.
	SessionReplayDropped
	// SessionTargetDenied fires when a client requested a target endpoint that
	// failed the allowed_targets filter. The SYN is silently dropped — this
	// event is the ONLY observability the operator gets.
	SessionTargetDenied
)

func (k SessionEventKind) String() string {
	switch k {
	case SessionEstablished:
		return "established"
	case SessionClosed:
		return "closed"
	case SessionAuthRejected:
		return "auth-rejected"
	case SessionReplayDropped:
		return "replay-dropped"
	case SessionTargetDenied:
		return "target-denied"
	}
	return "unknown"
}

// SessionEvent describes one session lifecycle or security transition.
type SessionEvent struct {
	Kind      SessionEventKind
	SessionID uint32
	Remote    netip.AddrPort
	Network   string
	Address   string
	Detail    string
}

// SetEventHandler registers a callback for session lifecycle and security
// events. The handler runs on a DEDICATED goroutine (never on receive paths):
// it may block, but sustained pressure causes drops — see EventsDropped. Panics
// in the handler are recovered. Call before Start.
func (s *Server) SetEventHandler(fn func(SessionEvent)) { s.events.setHandler(fn) }

// EventsDropped reports how many events were discarded because the handler
// could not keep up.
func (s *Server) EventsDropped() uint64 { return s.events.droppedCount() }

func (s *Server) emitSessionEvent(ev SessionEvent) { s.events.emit(ev) }

// ----- target filtering -----

// matchTargetPattern reports whether endpoint matches one allowed_targets
// pattern. Both sides use ParseTargetNetworkAndAddr semantics: the network
// (tcp/udp) must be equal, and the host:port part is matched with '*' (any
// sequence) and '?' (one character) wildcards, case-insensitively on the host.
func matchTargetPattern(pattern, endpoint string) bool {
	pNet, pRest := ParseTargetNetworkAndAddr(pattern)
	eNet, eRest := ParseTargetNetworkAndAddr(endpoint)
	if pNet != eNet {
		return false
	}
	pHost, pPort, pErr := net.SplitHostPort(pRest)
	eHost, ePort, eErr := net.SplitHostPort(eRest)
	if pErr != nil || eErr != nil {
		// A bare port ("22") is a valid Go addr form; fall back to whole-string
		// matching so such endpoints remain expressible.
		return wildcardMatch(strings.ToLower(pRest), strings.ToLower(eRest))
	}
	return wildcardMatch(strings.ToLower(pHost), strings.ToLower(eHost)) &&
		wildcardMatch(pPort, ePort)
}

// wildcardMatch is glob matching with '*' and '?' only (no escapes needed for
// hostnames and ports). Iterative two-pointer glob: backtracks only on the
// last '*'.
func wildcardMatch(pattern, s string) bool {
	var si, pi int
	star := -1
	starSi := 0
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			starSi = si
			pi++
			continue
		}
		if star >= 0 {
			pi = star + 1
			starSi++
			si = starSi
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// targetAllowed reports whether a client-requested endpoint may be forwarded.
// An empty pattern list never allows a request (default-target only).
func targetAllowed(endpoint string, patterns []string) bool {
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" && matchTargetPattern(p, endpoint) {
			return true
		}
	}
	return false
}

// defaultTargetDialer is the plain out-dial used when no TargetDialer is
// injected.
func defaultTargetDialer() TargetDialer {
	return func(ctx context.Context, _ uint32, network, address string) (net.Conn, error) {
		if network == "udp" {
			var d net.Dialer
			return d.DialContext(ctx, "udp", address)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	}
}

// ipOf returns the IP string of an AddrPort — the SYN-rate-limiter key.
//
// IPv4-mapped IPv6 addresses are unmapped first: a dual-stack socket can
// surface the same host as 192.0.2.7 and as ::ffff:192.0.2.7, and treating
// those as two keys would hand an attacker twice the burst (and a full extra
// bucket per host) simply by alternating address forms.
func ipOf(addr netip.AddrPort) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.Addr().Unmap().String()
}

// isClosedTransportErr reports whether a carrier error means "closed", which
// must end a read loop quietly rather than log a warning.
func isClosedTransportErr(err error) bool {
	return errors.Is(err, ErrClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}

// ----- synCache / synLimiter -----

// unackedPkt is one transmitted DATA record awaiting ACK. The wire bytes are
// immutable and reused verbatim on retransmission, which is what makes the
// PacketNo-derived nonce safe to reuse.
type unackedPkt struct {
	wire      []byte
	firstSent time.Time
	sentTime  time.Time
	rto       time.Duration
	retries   int
}

// synRecord caches the result of a verified handshake so a retransmitted or
// replayed SYN can be answered idempotently.
type synRecord struct {
	ackFrame  []byte
	createdAt time.Time
}

// synCacheKey maps a client nonce plus an opaque PSK-derived identifier to its
// verified handshake result. Including the credential identity prevents one
// authorized PSK from racing another PSK that intentionally reuses a nonce.
type synCacheKey struct {
	nonce [ClientNonceSize]byte
	pskID [16]byte
}

func makeSynCacheKey(nonce [ClientNonceSize]byte, synMACKey [32]byte) synCacheKey {
	var key synCacheKey
	key.nonce = nonce
	copy(key.pskID[:], synMACKey[:len(key.pskID)])
	return key
}

type synCache struct {
	mu      sync.Mutex
	entries map[synCacheKey]synRecord
	fifo    []synFIFOEntry
}

type synFIFOEntry struct {
	key       synCacheKey
	createdAt time.Time
}

func newSynCache() *synCache {
	return &synCache{entries: make(map[synCacheKey]synRecord)}
}

// Acquire atomically returns a completed cached ACK or reserves the key for
// exactly one handshake goroutine. A nil ACK with owner=false means another
// goroutine currently owns the same in-progress handshake.
func (c *synCache) Acquire(key synCacheKey, now time.Time) (ack []byte, owner bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec, ok := c.entries[key]; ok {
		if now.Sub(rec.createdAt) <= synCacheTTL {
			return rec.ackFrame, false
		}
		delete(c.entries, key)
	}
	c.makeSpaceLocked(now)
	c.entries[key] = synRecord{createdAt: now}
	c.fifo = append(c.fifo, synFIFOEntry{key: key, createdAt: now})
	return nil, true
}

// Complete publishes the immutable ACK for a key reserved by Acquire.
func (c *synCache) Complete(key synCacheKey, ackFrame []byte) {
	c.mu.Lock()
	if rec, ok := c.entries[key]; ok && rec.ackFrame == nil {
		rec.ackFrame = append([]byte(nil), ackFrame...)
		c.entries[key] = rec
	}
	c.mu.Unlock()
}

// Abort removes an in-progress reservation after a failed handshake.
func (c *synCache) Abort(key synCacheKey) {
	c.mu.Lock()
	if rec, ok := c.entries[key]; ok && rec.ackFrame == nil {
		delete(c.entries, key)
	}
	c.mu.Unlock()
}

func (c *synCache) makeSpaceLocked(now time.Time) {
	for key, rec := range c.entries {
		if now.Sub(rec.createdAt) > synCacheTTL {
			delete(c.entries, key)
		}
	}
	for len(c.entries) >= synCacheMax && len(c.fifo) > 0 {
		oldest := c.fifo[0]
		c.fifo = c.fifo[1:]
		if rec, ok := c.entries[oldest.key]; ok && rec.createdAt.Equal(oldest.createdAt) {
			delete(c.entries, oldest.key)
		}
	}
	if len(c.fifo) > synCacheMax*2 {
		fresh := c.fifo[:0]
		for _, item := range c.fifo {
			if rec, ok := c.entries[item.key]; ok && rec.createdAt.Equal(item.createdAt) {
				fresh = append(fresh, item)
			}
		}
		c.fifo = fresh
	}
}

// Len returns the number of cached nonces (used by tests).
func (c *synCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// synLimiter is a per-source-IP token bucket that throttles SYNs. A source IP
// gets `burst` tokens refilled at `rate` per second; when the map grows past
// 1024 buckets, long-idle ones are pruned.
type synLimiter struct {
	mu      sync.Mutex
	buckets map[string]*synBucket
	rate    float64
	burst   float64
}

type synBucket struct {
	tokens float64
	last   time.Time
}

func newSynLimiter(ratePerSec, burst float64) *synLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 5
	}
	if burst < 1 {
		burst = 10
	}
	return &synLimiter{buckets: make(map[string]*synBucket), rate: ratePerSec, burst: burst}
}

// Allow consumes one token for ip. It never blocks.
func (l *synLimiter) Allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= 1024 {
			for k, ob := range l.buckets {
				if now.Sub(ob.last) > time.Minute {
					delete(l.buckets, k)
				}
			}
		}
		b = &synBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Len returns the number of tracked source IPs (used by tests).
func (l *synLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// ----- ServerSession -----

// ServerSession is one established tunnel: a client on one side, a backend
// connection on the other. All record protection and ARQ state lives here.
type ServerSession struct {
	server        *Server
	sessionID     uint32
	raddr         netip.AddrPort
	raddrMu       sync.RWMutex
	targetNetwork string
	targetAddr    string
	upstream      net.Conn
	replayFilter  ReplayFilter

	// frameKeys is used by PSK-only sessions. Noise sessions use their transport
	// AEAD for both DATA and control records and leave this nil.
	frameKeys *FrameKeys

	sendPacketNo uint64
	sendSeq      uint64
	recvSeq      uint64

	rttEst *rttEstimator

	recvQueue map[uint64][]byte
	recvMu    sync.Mutex

	unacked     map[uint64]*unackedPkt
	unackedMu   sync.Mutex
	unackedCond *sync.Cond

	lastActive time.Time
	activeMu   sync.Mutex

	// pathID is the most recently observed inbound path. Server-initiated
	// traffic mirrors it so whatever demultiplexing the peer (and any NAT in
	// between) expects keeps working.
	pathID    PathID
	pathMu    sync.RWMutex
	pathValid bool

	challengeMu    sync.Mutex
	pathChallenges map[netip.Addr]pathChallenge

	closed    int32
	closeChan chan struct{}
	closeOnce sync.Once
}

func (sess *ServerSession) touch() {
	sess.activeMu.Lock()
	sess.lastActive = time.Now()
	sess.activeMu.Unlock()
}

func (sess *ServerSession) isClosed() bool { return atomic.LoadInt32(&sess.closed) == 1 }

func (sess *ServerSession) lastPath() (PathID, bool) {
	sess.pathMu.RLock()
	defer sess.pathMu.RUnlock()
	return sess.pathID, sess.pathValid
}

// setPath records the carrier path this session was most recently seen on.
func (sess *ServerSession) setPath(p PathID) {
	if !p.Peer.IsValid() {
		return
	}
	sess.pathMu.Lock()
	sess.pathID = p
	sess.pathValid = true
	sess.pathMu.Unlock()
}

func (sess *ServerSession) getRemoteAddr() netip.AddrPort {
	sess.raddrMu.RLock()
	defer sess.raddrMu.RUnlock()
	return sess.raddr
}

func (sess *ServerSession) sameRemoteIP(addr netip.AddrPort) bool {
	if !addr.IsValid() {
		return false
	}
	sess.raddrMu.RLock()
	current := sess.raddr
	sess.raddrMu.RUnlock()
	return current.IsValid() && current.Addr() == addr.Addr()
}

// updateRemoteAddr moves the session to a newly observed client address.
//
// A port-only change (same IP) is accepted after record authentication: it is
// plain NAT rebinding. An IP change is a genuine migration (WiFi -> cellular)
// and is worth an INFO line — but it is also exactly what a session hijacker
// needs, so callers must only set allowIPChange after AEAD authentication,
// replay filtering, and a bidirectional path challenge.
func (sess *ServerSession) updateRemoteAddr(newAddr netip.AddrPort, allowIPChange bool) {
	if !newAddr.IsValid() {
		return
	}
	sess.raddrMu.RLock()
	cur := sess.raddr
	sess.raddrMu.RUnlock()
	if cur == newAddr {
		return
	}
	sess.raddrMu.Lock()
	defer sess.raddrMu.Unlock()
	cur = sess.raddr
	if cur == newAddr {
		return
	}
	if !cur.IsValid() {
		sess.raddr = newAddr
		return
	}
	sameIP := cur.Addr() == newAddr.Addr()
	if !sameIP && !allowIPChange {
		sess.server.logWarn("[Session 0x%08X] ignored unvalidated address change %s -> %s (path challenge required)",
			sess.sessionID, cur, newAddr)
		return
	}
	atomic.AddUint64(&sess.server.addrChanges, 1)
	if sameIP {
		sess.server.logDebug("[Session 0x%08X] NAT rebinding (same IP, new port): %s -> %s",
			sess.sessionID, cur, newAddr)
	} else {
		sess.server.logInfo("[Session 0x%08X] connection migration: %s -> %s",
			sess.sessionID, cur, newAddr)
	}
	sess.raddr = newAddr
}

// processIncomingRecord is the complete post-handshake receive boundary. No
// session state may change until shape, authentication, packet-number replay
// and source-path checks all succeed.
func (sess *ServerSession) processIncomingRecord(rec *Record, path PathID) bool {
	if rec == nil || !validSessionRecordShape(rec) {
		return false
	}
	if !sess.verifyInboundRecord(rec, path) {
		return false
	}
	if !sess.replayFilter.Accept(rec.PacketNo) {
		atomic.AddUint64(&sess.server.replayDrops, 1)
		sess.server.emitSessionEvent(SessionEvent{
			Kind:      SessionReplayDropped,
			SessionID: sess.sessionID,
			Remote:    path.Peer,
			Network:   sess.targetNetwork,
			Address:   sess.targetAddr,
			Detail:    "packet number below the replay window",
		})
		if rec.Cmd == CmdData {
			sess.reackDuplicateData(path)
		}
		return false
	}
	if !sess.handleIncomingRecord(rec, path) {
		// DATA rejection is temporary (full application queue or an IP path
		// still being validated). Roll only DATA back so its byte-identical ARQ
		// retransmission can be accepted later. A rejected control record is
		// consumed permanently; otherwise an old ACK/FIN could be replayed
		// after a path migration completes.
		if rec.Cmd == CmdData {
			sess.replayFilter.Remove(rec.PacketNo)
		}
		return false
	}
	return true
}

// verifyInboundRecord opens the AEAD record in place before it may touch
// session state. Returns false when the record must be dropped.
func (sess *ServerSession) verifyInboundRecord(rec *Record, path PathID) bool {
	if sess.frameKeys == nil {
		return false
	}
	plain, err := OpenRecordAEAD(rec, sess.frameKeys.Recv)
	if err != nil {
		if n := atomic.AddUint64(&sess.server.macFailures, 1); n == 1 || n%100 == 0 {
			sess.server.logWarn("[Session 0x%08X] record authentication rejected cmd=0x%02X from %s: %v",
				sess.sessionID, rec.Cmd, path.Peer, err)
			sess.server.emitSessionEvent(SessionEvent{
				Kind:      SessionAuthRejected,
				SessionID: sess.sessionID,
				Remote:    path.Peer,
				Network:   sess.targetNetwork,
				Address:   sess.targetAddr,
				Detail:    fmt.Sprintf("cmd=0x%02X: %v", rec.Cmd, err),
			})
		}
		return false
	}
	rec.Data = plain
	// Tell the carrier a record verified. This is the one event it cannot see
	// for itself (it observes bytes, not a Poly1305 tag), and it is the only
	// evidence that clears a path the carrier had declared blocked.
	if sess.server.authFed != nil {
		sess.server.authFed.RecordAuthenticated()
	}
	return true
}

func (sess *ServerSession) handleIncomingRecord(rec *Record, path PathID) bool {
	if !sess.sameRemoteIP(path.Peer) {
		if rec.Cmd == CmdPathResponse && sess.acceptPathResponse(path.Peer, rec.Data) {
			sess.updateRemoteAddr(path.Peer, true)
			sess.setPath(path)
			sess.touch()
			return true
		}
		// Authentication proves who sent the record, while the challenge proves
		// the claimed new path can receive replies. DATA delivery, ACK/FIN
		// semantics and the stored route stay untouched until that response
		// returns. DATA's replay bit is rolled back by processIncomingRecord so
		// ARQ can retry it after migration.
		sess.sendPathChallenge(path)
		return false
	}
	if rec.Cmd == CmdData {
		// Record the observed path before dispatching: a DATA record that
		// kills the session (target write failure) must still leave a reply
		// path for the FIN that Close emits — otherwise the client hangs
		// until its own idle timeout.
		sess.setPath(path)
		return sess.handleDataFromPath(rec, path)
	}

	sess.updateRemoteAddr(path.Peer, false)
	sess.setPath(path)
	sess.touch()
	if rec.Ack > 0 {
		sess.handleAck(rec.Ack)
	}

	switch rec.Cmd {
	case CmdPing:
		pong := &Record{
			Magic:     sess.server.cfg.Magic,
			Version:   Version,
			Cmd:       CmdPong,
			SessionID: sess.sessionID,
			Ack:       sess.currentAck(),
		}
		sess.sendControl(pong, func(data []byte) error { return sess.replyOn(data, path) })
	case CmdFin:
		sess.server.logInfo("[Session 0x%08X] received FIN from client", sess.sessionID)
		sess.Close()
	}
	return true
}

func (sess *ServerSession) sendPathChallenge(path PathID) {
	var token [PathChallengeSize]byte
	now := time.Now()
	sess.challengeMu.Lock()
	if sess.pathChallenges == nil {
		sess.pathChallenges = make(map[netip.Addr]pathChallenge)
	}
	for ip, pending := range sess.pathChallenges {
		if now.After(pending.expires) {
			delete(sess.pathChallenges, ip)
		}
	}
	if pending, ok := sess.pathChallenges[path.Peer.Addr()]; ok {
		token = pending.token
	} else {
		if _, err := rand.Read(token[:]); err != nil {
			sess.challengeMu.Unlock()
			return
		}
		if len(sess.pathChallenges) >= maxPathChallenges {
			for ip := range sess.pathChallenges {
				delete(sess.pathChallenges, ip)
				break
			}
		}
		sess.pathChallenges[path.Peer.Addr()] = pathChallenge{token: token, expires: now.Add(pathChallengeTTL)}
	}
	sess.challengeMu.Unlock()

	challenge := &Record{
		Magic: sess.server.cfg.Magic, Version: Version,
		Cmd: CmdPathChallenge, SessionID: sess.sessionID, Data: token[:],
	}
	sess.sendControl(challenge, func(data []byte) error { return sess.replyOn(data, path) })
}

func (sess *ServerSession) acceptPathResponse(addr netip.AddrPort, data []byte) bool {
	if len(data) != PathChallengeSize {
		return false
	}
	sess.challengeMu.Lock()
	defer sess.challengeMu.Unlock()
	pending, ok := sess.pathChallenges[addr.Addr()]
	if !ok || time.Now().After(pending.expires) || !hmac.Equal(data, pending.token[:]) {
		return false
	}
	delete(sess.pathChallenges, addr.Addr())
	return true
}

// replyOn sends a record back along a specific observed path.
func (sess *ServerSession) replyOn(data []byte, path PathID) error {
	if err := sess.server.tr.ReplyRecord(data, path); err != nil {
		atomic.AddUint64(&sess.server.sendFailures, 1)
		return err
	}
	return nil
}

// sendToSession delivers data to the client on the most recently used path.
// On a request-driven carrier, ReplyRecord queues the record for the next
// inbound request to carry back; on a datagram carrier it goes out immediately.
func (sess *ServerSession) sendToSession(data []byte) {
	path, ok := sess.lastPath()
	if !ok {
		sess.server.logWarn("[Session 0x%08X] no observed path yet, dropping %d bytes", sess.sessionID, len(data))
		return
	}
	if err := sess.server.tr.ReplyRecord(data, path); err != nil {
		atomic.AddUint64(&sess.server.sendFailures, 1)
		sess.server.logWarn("[Session 0x%08X] reply failed: %v", sess.sessionID, err)
	}
}

func (sess *ServerSession) currentAck() uint64 {
	if next := atomic.LoadUint64(&sess.recvSeq); next > 0 {
		return next - 1
	}
	return 0
}

func (sess *ServerSession) handleAck(ackSeq uint64) {
	sess.unackedMu.Lock()
	if len(sess.unacked) == 0 {
		sess.unackedMu.Unlock()
		return
	}
	// ACKs are cumulative: "everything up to ackSeq has been delivered". This
	// matches the ACKs this end emits and keeps a lost ACK from leaving a
	// record stuck in the retransmit queue — any later ACK covers it.
	if pkt, ok := sess.unacked[ackSeq]; ok && pkt.retries == 0 {
		// Karn's rule: only sample RTT from a record that was never
		// retransmitted; the RTT of a retransmitted one is not trustworthy.
		sess.rttEst.Sample(time.Since(pkt.firstSent))
	}
	// Feed the carrier the wire size of every record this ACK retires. Only
	// records that were never retransmitted count: a retransmitted one proves
	// the path is marginal at that size, not that it is roomy.
	fed := sess.server.mtuFed
	for seq, pkt := range sess.unacked {
		if seq <= ackSeq {
			if fed != nil && pkt.retries == 0 {
				fed.RecordAcked(len(pkt.wire))
			}
			delete(sess.unacked, seq)
		}
	}
	sess.unackedMu.Unlock()
	// Free send-window space; broadcast outside the lock so a woken sender does
	// not immediately contend for the mutex we just released.
	sess.unackedCond.Broadcast()
}

func (sess *ServerSession) handleDataFromPath(rec *Record, path PathID) bool {
	// Authentication/decryption and packet-number replay filtering have already
	// completed in the receive path.
	payload := rec.Data
	if rec.Ack > 0 {
		sess.handleAck(rec.Ack)
	}

	expected := atomic.LoadUint64(&sess.recvSeq)
	if rec.Seq != expected {
		if rec.Seq < expected {
			// Already delivered. The peer is retransmitting because it never
			// saw our ACK, so re-ACK (cumulative) instead of silently dropping —
			// otherwise it would keep retrying until it gave up and tore the
			// session down.
			sess.sendCumulativeACK(expected-1, path)
			return true
		}
		// Out-of-order: buffer the payload and wait for the missing one to be
		// retransmitted. We deliberately do NOT Ack here, so the client keeps
		// the missing sequence outstanding and resends it.
		sess.recvMu.Lock()
		accepted := true
		if _, dup := sess.recvQueue[rec.Seq]; !dup {
			if len(sess.recvQueue) >= sess.server.maxRecvQueue {
				atomic.AddUint64(&sess.server.queueFullDrops, 1)
				accepted = false
			} else {
				sess.recvQueue[rec.Seq] = append([]byte(nil), payload...)
			}
		}
		sess.recvMu.Unlock()
		if accepted {
			sess.updateRemoteAddr(path.Peer, true)
			sess.setPath(path)
			sess.touch()
		}
		return accepted
	}

	// Only a fresh authenticated DATA record may migrate the session or install
	// a reply path.
	sess.updateRemoteAddr(path.Peer, true)
	sess.setPath(path)
	sess.touch()

	// In-order delivery. Gather the contiguous run (this record plus anything
	// already buffered behind it) under the lock, then deliver OUTSIDE the lock
	// so a slow target write cannot stall the receive path.
	type pending struct {
		seq     uint64
		payload []byte
	}
	run := []pending{{seq: expected, payload: payload}}
	sess.recvMu.Lock()
	next := expected + 1
	for {
		raw, ok := sess.recvQueue[next]
		if !ok {
			break
		}
		delete(sess.recvQueue, next)
		run = append(run, pending{seq: next, payload: raw})
		next++
	}
	sess.recvMu.Unlock()

	delivered := uint64(0)
	for _, p := range run {
		if err := sess.writeToTarget(p.payload); err != nil {
			sess.server.logWarn("[Session 0x%08X] target write failed: %v", sess.sessionID, err)
			sess.Close()
			return true
		}
		delivered++
	}
	if delivered == 0 {
		return true
	}
	atomic.StoreUint64(&sess.recvSeq, expected+delivered)

	// Ack the highest contiguous sequence just delivered.
	sess.sendCumulativeACK(expected+delivered-1, path)
	return true
}

// sendCumulativeACK emits an ACK meaning "everything up to ackSeq is
// delivered". Used after delivering a run and when re-ACKing a duplicate whose
// original ACK was lost.
func (sess *ServerSession) sendCumulativeACK(ackSeq uint64, path PathID) {
	ackFrame := &Record{
		Magic:      sess.server.cfg.Magic,
		Version:    Version,
		Cmd:        CmdAck,
		SessionID:  sess.sessionID,
		Ack:        ackSeq,
		WindowSize: 65535,
	}
	sess.sendControl(ackFrame, func(data []byte) error { return sess.replyOn(data, path) })
}

func (sess *ServerSession) reackDuplicateData(path PathID) {
	if ack := sess.currentAck(); ack > 0 {
		sess.sendCumulativeACK(ack, path)
	}
}

func (sess *ServerSession) writeToTarget(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if sess.upstream == nil {
		return errors.New("target connection unavailable")
	}
	if sess.targetNetwork == "udp" {
		n, err := sess.upstream.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	return writeAll(sess.upstream, data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// encodeRecord assigns a fresh per-direction packet number and seals the record
// as a ChaCha20-Poly1305 record. The buffer is freshly allocated: only use for
// records whose wire bytes are retained (DATA).
func (sess *ServerSession) encodeRecord(r *Record) []byte {
	r.PacketNo = atomic.AddUint64(&sess.sendPacketNo, 1)
	if r.PacketNo == 0 || sess.frameKeys == nil {
		return nil
	}
	return SealRecordAEAD(r, sess.frameKeys.Send, r.Data, sess.server.maxRecordSize)
}

// sendControl seals a control record and hands it to send. Returns false when
// the session lacks record protection or the packet-number space is exhausted.
func (sess *ServerSession) sendControl(r *Record, send func([]byte) error) bool {
	r.PacketNo = atomic.AddUint64(&sess.sendPacketNo, 1)
	if r.PacketNo == 0 || sess.frameKeys == nil {
		return false
	}
	wire := SealRecordAEAD(r, sess.frameKeys.Send, r.Data, sess.server.maxRecordSize)
	if len(wire) == 0 {
		return false
	}
	_ = send(wire)
	return true
}

// sendData assigns a sequence number, records the record for retransmission and
// pushes it out. It blocks while the send window is full (backpressure): the
// target read loop stops reading until ACKs arrive, which is what keeps the
// unacked map and the retransmit backlog bounded for a stalled client.
func (sess *ServerSession) sendData(payload []byte) error {
	if len(payload) > sess.server.maxPayload {
		return fmt.Errorf("payload of %d bytes exceeds the carrier payload budget (%d): chunk writes to %d bytes or smaller",
			len(payload), sess.server.maxPayload, sess.server.maxPayload)
	}
	sess.unackedMu.Lock()
	for len(sess.unacked) >= sess.server.sendWindow && !sess.isClosed() {
		sess.unackedCond.Wait()
	}
	sess.unackedMu.Unlock()
	if sess.isClosed() {
		return ErrClosed
	}

	seq := atomic.AddUint64(&sess.sendSeq, 1) - 1
	rec := &Record{
		Magic:      sess.server.cfg.Magic,
		Version:    Version,
		Cmd:        CmdData,
		SessionID:  sess.sessionID,
		Seq:        seq,
		Ack:        sess.currentAck(),
		WindowSize: 65535,
		Data:       payload,
	}
	encoded := sess.encodeRecord(rec)
	if len(encoded) == 0 {
		return errors.New("failed to seal DATA record")
	}

	sess.unackedMu.Lock()
	now := time.Now()
	sess.unacked[seq] = &unackedPkt{
		wire:      encoded,
		firstSent: now,
		sentTime:  now,
		rto:       sess.rttEst.RTO(),
	}
	sess.unackedMu.Unlock()

	// Server-initiated: mirror the most recently observed path so whatever
	// demultiplexing the peer requires keeps working.
	sess.sendToSession(encoded)
	return nil
}

// upstreamLoop pumps the backend connection into the tunnel. For "udp" targets
// the backend Write preserved datagram boundaries, so the end-to-end datagram
// semantics hold (one target datagram = one DATA record). For stream targets
// the loop ships whatever chunk the next Read returns.
func (sess *ServerSession) upstreamLoop() {
	defer sess.Close()
	bufSize := sess.server.maxPayload
	if bufSize <= 0 {
		bufSize = MaxPayloadLen
	}
	buf := make([]byte, bufSize)
	for {
		if sess.isClosed() {
			return
		}
		// Follow the carrier's live budget so an adaptive MTU keeps the backend
		// reads chunked to what the path can actually carry. A UDP target keeps
		// whole datagrams, so only a stream target is chunked here: shrinking a
		// UDP read would silently truncate a datagram instead of splitting it.
		limit := bufSize
		if sess.targetNetwork != "udp" {
			if budget := sess.server.sendPayloadBudget(); budget > 0 && budget < limit {
				limit = budget
			}
		}
		n, err := sess.upstream.Read(buf[:limit])
		if err != nil {
			if sess.targetNetwork == "tcp" && !errors.Is(err, io.EOF) && !isClosedTransportErr(err) {
				var ne net.Error
				if !errors.As(err, &ne) {
					sess.server.logWarn("[Session 0x%08X] target read error: %v", sess.sessionID, err)
				}
			}
			return
		}
		if n > 0 {
			sess.touch()
			if err := sess.sendData(buf[:n]); err != nil {
				return
			}
		}
	}
}

func (sess *ServerSession) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-sess.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			// The carrier may declare a floor far above the estimator's RTO —
			// a throttled path cannot answer faster than its own pace, and a
			// blocked one must not be probed faster than its block timeout, or
			// every retransmit is more fuel on a fire that is already being
			// rate-limited. Re-read it each tick because it moves with the
			// carrier's classification.
			floor := rtoFloorOf(sess.server.tr)
			fed := sess.server.mtuFed
			sess.unackedMu.Lock()
			for seq, pkt := range sess.unacked {
				wait := pkt.rto
				if wait < floor {
					wait = floor
				}
				if now.Sub(pkt.sentTime) < wait {
					continue
				}
				if pkt.retries >= 15 {
					sess.server.logWarn("[Session 0x%08X] max retries reached for Seq %d, closing session", sess.sessionID, seq)
					if fed != nil {
						// One more record that exhausted its retransmissions at
						// this size is exactly the evidence in-band MTU
						// adaptation shrinks on (when the carrier is healthy
						// enough for the signal to be trusted).
						fed.RecordLost(len(pkt.wire))
					}
					sess.unackedMu.Unlock()
					sess.Close()
					return
				}
				pkt.retries++
				pkt.sentTime = now
				pkt.rto = minDuration(pkt.rto*3/2, sess.rttEst.maxRTT)
				sess.sendToSession(pkt.wire)
			}
			sess.unackedMu.Unlock()
		}
	}
}

// Close tears the session down exactly once.
func (sess *ServerSession) Close() {
	sess.closeOnce.Do(func() {
		atomic.StoreInt32(&sess.closed, 1)
		// Wake senders parked on the send window before anything else touches
		// the mutex they are waiting on.
		sess.unackedMu.Lock()
		sess.unackedCond.Broadcast()
		sess.unackedMu.Unlock()
		// Notify the client before tearing local state down: the client
		// handles FIN by closing its local end immediately, which is what
		// turns a server-side teardown (target write failure, idle timeout,
		// max retries) into a prompt local error instead of an application
		// hanging until its own idle timeout. Best effort — the peer may
		// already be gone, and the carrier may already be closed.
		sess.sendControl(&Record{
			Magic:     sess.server.cfg.Magic,
			Version:   Version,
			Cmd:       CmdFin,
			SessionID: sess.sessionID,
		}, func(data []byte) error { sess.sendToSession(data); return nil })
		close(sess.closeChan)
		if sess.upstream != nil {
			_ = sess.upstream.Close()
		}
		sess.server.sessions.Delete(sess.sessionID)
		sess.server.logInfo("[Session 0x%08X] session closed", sess.sessionID)
		sess.server.emitSessionEvent(SessionEvent{
			Kind:      SessionClosed,
			SessionID: sess.sessionID,
			Remote:    sess.getRemoteAddr(),
			Network:   sess.targetNetwork,
			Address:   sess.targetAddr,
		})
	})
}

// minDuration returns the smaller of two durations.
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
