package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// icmp_custom CLIENT.
//
// The client is the mirror image of the server: it accepts ordinary
// application connections locally and tunnels each one to the server, which
// forwards it to the real backend:
//
//	app ──tcp──► client ──v2 records over ICMP Echo──► server ──tcp──► backend
//
// On a request-driven carrier (ICMP) every client→server record must ride an
// Echo Request, so `send` is a Poke rather than a fire-and-forget write, and
// downlink is pulled by keeping a small window of requests in flight. On a
// datagram carrier the same code writes records directly and replies come back
// asynchronously — the session layer does not care which.

const (
	clientMaxHandshakeAttempts = 8
	clientHandshakeBackoff     = 400 * time.Millisecond
	clientRecvTimeout          = 75 * time.Second // > the server's 60s idle cleanup
	clientMaxRetries           = 15
	clientRetransmitInterval   = 50 * time.Millisecond
)

// Defaults for the request-driven poll scheduler.
const (
	defaultPollsInFlight    = 4
	defaultPollInterval     = 20 * time.Millisecond
	defaultIdlePollInterval = time.Second
	defaultKeepAlive        = 15 * time.Second
)

// ClientConfig configures a Client.
//
// As with ServerConfig, the UDP profile's port-spreading knobs
// (`port_range` / `origdst` / `sendsock_max` / `receive_sockets`) simply do not
// exist here; unknown JSON keys are ignored.
type ClientConfig struct {
	// Transport names the carrier. Only "icmp" exists in this project; an
	// empty value selects it. Any other value is rejected by NewClient before
	// a socket is opened.
	Transport string `json:"transport"`
	// ICMP is the ICMP carrier profile (and the source of the poll schedule,
	// which on a request-driven carrier IS the downlink throughput ceiling).
	// Read by NewClient, not by NewClientWithTransport.
	ICMP ICMPProfile `json:"icmp"`
	// ServerAddr is the peer to tunnel to. ICMP binds no port, so a bare host
	// ("2001:db8::1") is the natural form; a "host:port" is accepted and the
	// port ignored. The carrier decides the address family.
	ServerAddr string `json:"server"`
	// Target is the forwarding endpoint REQUESTED in the handshake, e.g.
	// "tcp://127.0.0.1:22". Empty asks for the server's default target. The
	// server only honors requests that pass its allowed_targets filter; a
	// denied request means the handshake never completes.
	Target string `json:"target"`
	// Passwords are the PSKs; at least one non-blank is mandatory.
	Passwords []string `json:"passwords"`
	// Magic must match the server's. Zero selects MagicDefault.
	Magic uint32 `json:"magic"`
	// ServerPub is the server's Noise static public key. The zero value selects
	// PSK-only mode (still confidential, but without forward secrecy).
	ServerPub [32]byte `json:"-"`
	// SendWindow caps DATA records in flight before backpressure (0 = 256).
	SendWindow int `json:"send_window"`
	// ListenAddr is the local address applications connect to when the client
	// runs in CLI mode, e.g. "127.0.0.1:1080". Embedders that only use
	// DialTunnel leave it empty.
	ListenAddr string `json:"listen"`
	// LogLevel is debug|info|warn|error. Ignored when Logger is set.
	LogLevel string `json:"log_level"`
	// Logger receives diagnostics (pass Nop for silence).
	Logger Logger `json:"-"`

	// Poll tuning, honoured only by request-driven carriers (ICMP).
	PollsInFlight    int           `json:"polls_in_flight"`  // in-flight requests; 0 = 4
	PollInterval     time.Duration `json:"poll_interval_ms"` // active poll spacing; 0 = 20ms
	IdlePollInterval time.Duration `json:"idle_poll_ms"`     // idle poll spacing; 0 = 1s
	KeepAlive        time.Duration `json:"keepalive_ms"`     // deep-idle spacing; 0 = 15s

	// Handshake retry tuning. ICMP paths often have a higher RTT and may be
	// rate-limited, so both are configurable; the defaults are tuned for a
	// typical WAN (8 attempts, 400ms x attempt).
	HandshakeAttempts int           `json:"handshake_attempts"`   // 0 = 8
	HandshakeBackoff  time.Duration `json:"handshake_backoff_ms"` // 0 = 400ms

	// ProtectFD, when set, is called with each carrier socket descriptor so an
	// Android VpnService can exempt it from its own tunnel. Unused on desktop.
	ProtectFD func(fd int) error `json:"-"`
}

func (cfg ClientConfig) pollsInFlight() int {
	if cfg.PollsInFlight > 0 {
		return cfg.PollsInFlight
	}
	return defaultPollsInFlight
}

func (cfg ClientConfig) pollInterval() time.Duration {
	if cfg.PollInterval > 0 {
		return cfg.PollInterval
	}
	return defaultPollInterval
}

func (cfg ClientConfig) idlePoll() time.Duration {
	if cfg.IdlePollInterval > 0 {
		return cfg.IdlePollInterval
	}
	return defaultIdlePollInterval
}

func (cfg ClientConfig) keepAlive() time.Duration {
	if cfg.KeepAlive > 0 {
		return cfg.KeepAlive
	}
	return defaultKeepAlive
}

func (cfg ClientConfig) handshakeAttempts() int {
	if cfg.HandshakeAttempts > 0 {
		return cfg.HandshakeAttempts
	}
	return clientMaxHandshakeAttempts
}

func (cfg ClientConfig) handshakeBackoff() time.Duration {
	if cfg.HandshakeBackoff > 0 {
		return cfg.HandshakeBackoff
	}
	return clientHandshakeBackoff
}

// Client fronts local applications and tunnels them to one peer.
type Client struct {
	cfg        ClientConfig
	magic      uint32
	logger     Logger
	tr         Transport
	serverAddr netip.AddrPort

	maxRecordSize int
	maxPayload    int

	// mtuFed and authFed are the carrier's optional feedback capabilities,
	// resolved once (the carrier is immutable). Both are nil for an ordinary
	// carrier and every use is nil-checked.
	mtuFed  MTUFeedback
	authFed AuthenticatedFeedback

	sessions sync.Map // sessionID -> *clientSession

	// startOnce guards the lazily-started receive loop (the DialTunnel path;
	// Start starts it eagerly).
	startOnce sync.Once
	wg        sync.WaitGroup

	// Handshake ACKs echo ClientNonce, so independent local connections can
	// establish concurrently without a global handshake lock.
	ackMu       sync.Mutex
	pendingAcks map[[ClientNonceSize]byte]*pendingHandshake

	events *eventBus[ClientEvent]

	closeOnce sync.Once
	closeChan chan struct{}
	closed    int32
}

// NewClientWithTransport builds a client on an injected carrier. It is the
// injection seam used by tests, by embedders and by the profile-default
// constructors.
func NewClientWithTransport(cfg ClientConfig, tr Transport) (*Client, error) {
	if tr == nil {
		return nil, errors.New("client: transport is required")
	}
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return nil, fmt.Errorf("%w: client requires 'server'", ErrConfigRequired)
	}
	passwords := make([]string, 0, len(cfg.Passwords))
	for _, password := range cfg.Passwords {
		if password = strings.TrimSpace(password); password != "" {
			passwords = append(passwords, password)
		}
	}
	if len(passwords) == 0 {
		return nil, fmt.Errorf("%w: client requires at least one password (PSK)", ErrConfigRequired)
	}
	cfg.Passwords = passwords
	if cfg.Magic == 0 {
		cfg.Magic = MagicDefault
	}
	if cfg.SendWindow <= 0 {
		cfg.SendWindow = defaultSendWindow
	}
	serverAddr, err := parsePeerAddr(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("client: invalid 'server' %q: %w", cfg.ServerAddr, err)
	}
	return &Client{
		cfg:    cfg,
		magic:  cfg.Magic,
		logger: resolveLogger(cfg.Logger, cfg.LogLevel),
		tr:     tr,
		// The record ceiling is the RECEIVE ceiling, not the carrier's live send
		// budget: it covers whatever the peer may legitimately send, so it is
		// sized once from the fixed value and drives the read buffer, Parse and
		// the seal limit.
		serverAddr:    serverAddr,
		maxRecordSize: maxReceiveSizeOf(tr),
		maxPayload:    MaxPayloadFor(maxReceiveSizeOf(tr)),
		mtuFed:        mtuFeedbackOf(tr),
		authFed:       authenticatedFeedbackOf(tr),
		pendingAcks:   make(map[[ClientNonceSize]byte]*pendingHandshake),
		events:        newEventBus[ClientEvent](128),
		closeChan:     make(chan struct{}),
	}, nil
}

// sendPayloadBudget is the largest DATA payload the carrier can carry RIGHT
// NOW, re-read per use so an adaptive carrier's MTU moves the record size the
// session emits without the session knowing why.
func (c *Client) sendPayloadBudget() int {
	return payloadBudgetOf(c.tr, c.maxPayload)
}

// parsePeerAddr accepts "host" or "host:port" and returns an AddrPort with port
// 0 when no port is given (ICMP has no ports, so the value is a placeholder).
func parsePeerAddr(s string) (netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, 0), nil
}

// ClientEventKind enumerates the client-side lifecycle notifications.
type ClientEventKind int

const (
	// TunnelEstablished fires on the DialTunnel caller's goroutine right after
	// a handshake completes.
	TunnelEstablished ClientEventKind = iota
	// TunnelDied fires when a session ends (reason in Detail).
	TunnelDied
	// Reconnecting fires before each re-dial attempt made by AutoReconnect
	// (nth attempt in Attempt, starting at 1).
	Reconnecting
	// HandshakeRetrying fires when a SYN timed out and the client is about to
	// retransmit (Attempt = the upcoming attempt number).
	HandshakeRetrying
)

func (k ClientEventKind) String() string {
	switch k {
	case TunnelEstablished:
		return "established"
	case TunnelDied:
		return "died"
	case Reconnecting:
		return "reconnecting"
	case HandshakeRetrying:
		return "handshake-retrying"
	}
	return "unknown"
}

// ClientEvent is one client-side lifecycle notification.
type ClientEvent struct {
	Kind    ClientEventKind
	Session uint32 // session ID when known, 0 during handshakes
	Detail  string
	Attempt int // Reconnecting / HandshakeRetrying only
}

type pendingHandshake struct {
	ackMAC [32]byte
	ch     chan *Record
}

// DialOptions carries the per-tunnel parameters for Client.DialTunnel.
type DialOptions struct {
	// Target requests the forwarding endpoint. Empty = the server's default
	// target. The request must pass the server's allowed_targets filter or the
	// handshake never completes (denied SYNs are silently dropped).
	Target string
	// OnGranted, when set, receives the endpoint the server actually granted
	// ("" = the server default) once the handshake succeeds.
	OnGranted func(granted string)
}

// Start blocks: it serves local applications until Close is called. This is the
// CLI-facing mode; embedders that want single connections use DialTunnel.
func (c *Client) Start() error {
	if strings.TrimSpace(c.cfg.ListenAddr) == "" {
		return fmt.Errorf("%w: client 'listen' is required for Start (CLI mode); embedders use DialTunnel instead", ErrConfigRequired)
	}
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("client listen %s: %w", c.cfg.ListenAddr, err)
	}
	c.startRecvLoop()
	c.logInfo("[Client] listening on %s", ln.Addr())
	c.logInfo("[Client] tunnel to peer %s (carrier %s)", c.cfg.ServerAddr, c.tr.RemoteID())
	if c.cfg.Target != "" {
		c.logInfo("[Client] requested target: %s", c.cfg.Target)
	}

	go func() {
		<-c.closeChan
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&c.closed) == 1 {
				return nil
			}
			return fmt.Errorf("client accept: %w", err)
		}
		c.wg.Add(1)
		go func(conn net.Conn) {
			defer c.wg.Done()
			c.serveConn(conn, c.cfg.Target)
		}(conn)
	}
}

// serveConn fronts one accepted local connection for its whole lifetime.
func (c *Client) serveConn(conn net.Conn, target string) {
	sess, err := c.establish(context.Background(), target, conn)
	if err != nil {
		c.logError("[Client] handshake failed for %s: %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}
	<-sess.closeChan
}

// SetEventHandler registers a callback for client lifecycle events. The handler
// runs on a DEDICATED goroutine (never on receive paths): it may block, but
// under sustained pressure slow handlers cause drops. Panics are recovered.
func (c *Client) SetEventHandler(h func(ClientEvent)) { c.events.setHandler(h) }

// EventsDropped reports how many events were discarded because the handler
// could not keep up.
func (c *Client) EventsDropped() uint64 { return c.events.droppedCount() }

func (c *Client) logDebug(format string, args ...any) { c.logger.Debugf(format, args...) }
func (c *Client) logInfo(format string, args ...any)  { c.logger.Infof(format, args...) }
func (c *Client) logWarn(format string, args ...any)  { c.logger.Warnf(format, args...) }
func (c *Client) logError(format string, args ...any) { c.logger.Errorf(format, args...) }

// startRecvLoop launches the single carrier receive goroutine (idempotent).
func (c *Client) startRecvLoop() {
	c.startOnce.Do(func() {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.readLoop()
		}()
	})
}

// readLoop is the single receive path shared by every tunnel of this client.
func (c *Client) readLoop() {
	bufSize := c.maxRecordSize
	if bufSize <= 0 {
		bufSize = maxWireRecordSize
	}
	buf := make([]byte, bufSize)
	for {
		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}
		n, _, err := c.tr.ReadRecord(buf)
		if err != nil {
			if atomic.LoadInt32(&c.closed) == 1 || isClosedTransportErr(err) {
				return
			}
			c.logWarn("[Client] carrier read error: %v", err)
			return
		}
		var rec Record
		if err := Parse(buf[:n], c.magic, c.maxRecordSize, &rec); err != nil {
			continue // junk, a foreign reply, or a truncated record
		}
		c.dispatch(buf[:n], &rec)
	}
}

func (c *Client) dispatch(raw []byte, rec *Record) {
	if rec.Cmd == CmdHandshakeAck {
		if rec.SessionID == 0 || rec.PacketNo != 0 || rec.Seq != 0 || rec.Ack != 0 || len(rec.Data) < AckPayloadBase {
			return
		}
		var clientNonce [ClientNonceSize]byte
		copy(clientNonce[:], rec.Data[:ClientNonceSize])
		c.ackMu.Lock()
		pending := c.pendingAcks[clientNonce]
		c.ackMu.Unlock()
		// Authenticate before enqueueing so a forged burst cannot occupy the
		// bounded candidate queue and starve the genuine server response.
		if pending != nil && VerifyMAC(rec.Raw(), &pending.ackMAC, c.maxRecordSize) == nil {
			owned, err := ParseOwned(raw, c.magic, c.maxRecordSize)
			if err == nil {
				select {
				case pending.ch <- owned:
				default:
				}
			}
		}
		return
	}

	v, ok := c.sessions.Load(rec.SessionID)
	if !ok {
		c.logDebug("[Client] record for unknown session 0x%08X (cmd=%d)", rec.SessionID, rec.Cmd)
		return
	}
	sess := v.(*clientSession)
	if !validSessionRecordShape(rec) {
		return
	}
	if sess.frameKeys == nil {
		return
	}
	plain, err := OpenRecordAEAD(rec, sess.frameKeys.Recv)
	if err != nil {
		c.logDebug("[Client] [Session 0x%08X] record authentication rejected cmd=0x%02X: %v", sess.sid, rec.Cmd, err)
		return
	}
	rec.Data = plain
	// Tell the carrier a record verified: it observes bytes, not tags, and this
	// is the only evidence that clears a path it had declared blocked.
	if c.authFed != nil {
		c.authFed.RecordAuthenticated()
	}
	sess.noteAnswered()
	if !sess.replayFilter.Accept(rec.PacketNo) {
		if rec.Cmd == CmdData {
			sess.reackDuplicateData()
		}
		return
	}
	if rec.Ack > 0 {
		sess.handleAck(rec.Ack)
	}
	switch rec.Cmd {
	case CmdData:
		if !sess.handleData(rec) {
			sess.replayFilter.Remove(rec.PacketNo)
		}
	case CmdAck:
		sess.touch()
	case CmdPing:
		sess.touch()
		pong := &Record{Magic: c.magic, Version: Version, Cmd: CmdPong, SessionID: sess.sid, Ack: sess.currentAck()}
		sess.sendControl(pong, sess.poke)
	case CmdPong:
		sess.touch()
	case CmdFin:
		c.logInfo("[Client] [Session 0x%08X] server sent FIN", sess.sid)
		sess.closeWithReason("server sent FIN")
	case CmdPathChallenge:
		response := &Record{
			Magic: c.magic, Version: Version, Cmd: CmdPathResponse,
			SessionID: sess.sid, Data: append([]byte(nil), rec.Data...),
		}
		sess.sendControl(response, sess.poke)
	}
}

// DialTunnel establishes one tunnel session and returns its local end as a
// net.Conn: writes are tunneled to the granted target, reads return the
// target's responses.
//
// Errors: ErrClosed after Client.Close, ErrHandshakeTimeout when the peer never
// answers (unreachable / PSK mismatch / target denied), ctx.Err() on
// cancellation — all matchable via errors.Is.
//
// The returned conn is a *TunnelSession, which additionally exposes Done()
// (closed when the session ends for any reason) and Err() (the terminal cause).
func (c *Client) DialTunnel(ctx context.Context, opts DialOptions) (net.Conn, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return nil, ErrClosed
	}
	c.startRecvLoop()

	appConn, sessionConn := net.Pipe()
	type established struct {
		sess *clientSession
		err  error
	}
	done := make(chan established, 1)
	go func() {
		sess, err := c.establish(ctx, opts.Target, sessionConn)
		done <- established{sess, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			appConn.Close()
			return nil, r.err
		}
		if opts.OnGranted != nil {
			// Runs on the DialTunnel caller's goroutine, before the first byte
			// can flow — embedders may rely on that ordering.
			opts.OnGranted(r.sess.granted)
		}
		return newTunnelSession(appConn, r.sess), nil
	case <-ctx.Done():
		// The handshake may still be in flight; it cleans up after itself, and
		// once it lands, closing both pipe ends tears any session down.
		go func() {
			r := <-done
			appConn.Close()
			sessionConn.Close()
			if r.err == nil && r.sess != nil {
				r.sess.close()
			}
		}()
		return nil, ctx.Err()
	}
}

// establish performs the handshake, registers the session and starts its pump
// loops. conn is the caller-supplied local end.
func (c *Client) establish(ctx context.Context, target string, conn net.Conn) (*clientSession, error) {
	sid, frameKeys, granted, err := c.handshake(ctx, target)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		c.events.emit(ClientEvent{Kind: TunnelDied, Detail: "handshake failed: " + err.Error()})
		return nil, err
	}
	if granted != "" && granted != target {
		c.logInfo("[Client] [Session 0x%08X] server granted target %s (requested %s)", sid, granted, target)
	}

	sess := &clientSession{
		client:     c,
		sid:        sid,
		conn:       conn,
		frameKeys:  frameKeys,
		granted:    granted,
		sendSeq:    1,
		recvSeq:    1,
		recvQueue:  make(map[uint64][]byte),
		unacked:    make(map[uint64]*unackedPkt),
		lastActive: time.Now(),
		lastSent:   time.Now(),
		closeChan:  make(chan struct{}),
		rttEst:     newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	c.sessions.Store(sid, sess)
	c.logInfo("[Client] [Session 0x%08X] tunnel established", sid)
	c.events.emit(ClientEvent{Kind: TunnelEstablished, Session: sid, Detail: granted})

	go func() {
		defer c.sessions.Delete(sid)
		defer conn.Close()
		sess.localToRemote()
		sess.close()
	}()
	go sess.retransmitLoop()
	go sess.keepAliveLoop()
	go sess.pollLoop()
	go func() {
		<-sess.closeChan
		sess.closeReasonMu.Lock()
		reason := sess.closeReason
		sess.closeReasonMu.Unlock()
		c.events.emit(ClientEvent{Kind: TunnelDied, Session: sid, Detail: reason})
	}()
	return sess, nil
}

// handshake sends the SYN (retransmitting until the ACK arrives) and returns
// the new SessionID, the record protection, and the target the server actually
// granted ("" for the server's default). The request rides inside the MAC'd SYN
// payload; a server that does not allow it silently drops the SYN, which
// surfaces here as "no handshake ACK". Retransmissions reuse the exact SYN, so
// the server's nonce cache answers with the exact same ACK and session.
func (c *Client) handshake(ctx context.Context, target string) (uint32, *FrameKeys, string, error) {
	if len(target) > TargetMaxLen {
		return 0, nil, "", fmt.Errorf("target %q exceeds %d bytes", target, TargetMaxLen)
	}
	var nk *ClientNK
	var msg1 []byte
	var zero [32]byte
	encrypted := c.cfg.ServerPub != zero
	if encrypted {
		var err error
		nk, err = NewClientNK(c.cfg.ServerPub)
		if err != nil {
			return 0, nil, "", err
		}
		msg1, err = nk.Message1()
		if err != nil {
			return 0, nil, "", err
		}
	}

	var clientNonce [ClientNonceSize]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return 0, nil, "", fmt.Errorf("nonce: %w", err)
	}
	handshakeKeys := DerivePSKHandshakeKeys(c.cfg.Passwords[0], clientNonce)

	// [16B ClientNonce] [8B Timestamp] [target TLV] [optional 48B msg1].
	payload := make([]byte, SynPayloadBase)
	copy(payload[:ClientNonceSize], clientNonce[:])
	binary.BigEndian.PutUint64(payload[ClientNonceSize:SynPayloadBase], uint64(time.Now().Unix()))
	payload = appendTargetTLV(payload, target)
	payload = append(payload, msg1...)

	syn := SealMAC(&Record{
		Magic: c.magic, Version: Version,
		Cmd: CmdHandshakeSyn, Data: payload,
	}, &handshakeKeys.SynMAC, c.maxRecordSize)
	if len(syn) == 0 {
		return 0, nil, "", errors.New("failed to seal SYN")
	}

	ch := make(chan *Record, 8)
	c.ackMu.Lock()
	if _, exists := c.pendingAcks[clientNonce]; exists {
		c.ackMu.Unlock()
		return 0, nil, "", ErrNonceCollision
	}
	c.pendingAcks[clientNonce] = &pendingHandshake{ackMAC: handshakeKeys.AckMAC, ch: ch}
	c.ackMu.Unlock()
	defer func() {
		c.ackMu.Lock()
		delete(c.pendingAcks, clientNonce)
		c.ackMu.Unlock()
	}()

	for attempt := 1; attempt <= c.cfg.handshakeAttempts(); attempt++ {
		if err := c.sendHandshakeRecord(syn); err != nil {
			c.logDebug("[Client] handshake attempt %d send failed: %v", attempt, err)
		}
		timer := time.NewTimer(c.cfg.handshakeBackoff() * time.Duration(attempt))
		waiting := true
		for waiting {
			select {
			case ack := <-ch:
				// An unauthenticated forged ACK is noise, not a terminal
				// handshake error. Keep waiting for the genuine response.
				if err := VerifyMAC(ack.Raw(), &handshakeKeys.AckMAC, c.maxRecordSize); err != nil {
					c.logDebug("[Client] ignored invalid handshake ACK: %v", err)
					continue
				}
				granted, noiseMsg2, err := splitAckPayload(ack.Data, encrypted)
				if err != nil {
					timer.Stop()
					return 0, nil, "", fmt.Errorf("authenticated handshake ACK payload: %w", err)
				}
				var echoedNonce [ClientNonceSize]byte
				copy(echoedNonce[:], ack.Data[:ClientNonceSize])
				if echoedNonce != clientNonce {
					continue
				}
				var serverNonce [ServerNonceSize]byte
				copy(serverNonce[:], ack.Data[ClientNonceSize:AckPayloadBase])
				if !encrypted {
					keys := DerivePSKSessionKeys(c.cfg.Passwords[0], clientNonce, serverNonce, ack.SessionID)
					frameKeys, err := keys.ClientFrameCiphers()
					if err != nil {
						timer.Stop()
						return 0, nil, "", fmt.Errorf("session cipher init: %w", err)
					}
					timer.Stop()
					return ack.SessionID, frameKeys, granted, nil
				}
				sess, err := nk.Finish(noiseMsg2)
				if err != nil {
					timer.Stop()
					return 0, nil, "", fmt.Errorf("noise finish: %w", err)
				}
				c.logInfo("[Client] Noise_NK established (channel binding %x...)", sess.HandshakeHash[:4])
				timer.Stop()
				return ack.SessionID, &FrameKeys{Send: sess.SendCipher, Recv: sess.RecvCipher}, granted, nil
			case <-timer.C:
				c.logDebug("[Client] handshake attempt %d timed out, retrying", attempt)
				if attempt < c.cfg.handshakeAttempts() {
					c.events.emit(ClientEvent{Kind: HandshakeRetrying, Attempt: attempt + 1})
				}
				waiting = false
			case <-c.closeChan:
				timer.Stop()
				return 0, nil, "", ErrClosed
			case <-ctx.Done():
				timer.Stop()
				return 0, nil, "", ctx.Err()
			}
		}
	}
	return 0, nil, "", fmt.Errorf("%w (check: peer reachable? same PSK on both ends? requested target allowed by the peer's allowed_targets? — denied requests are silently dropped)", ErrHandshakeTimeout)
}

// sendHandshakeRecord transmits a pre-encoded handshake record. On a
// request-driven carrier the SYN is a request and the ACK comes back as its
// reply; on a datagram carrier it is a plain write.
func (c *Client) sendHandshakeRecord(wire []byte) error {
	if p := pollerOf(c.tr); p != nil {
		_, err := p.Poke(wire, c.serverAddr)
		return err
	}
	return c.tr.WriteRecord(wire, c.serverAddr)
}

// TunnelSession is the net.Conn returned by DialTunnel plus session-lifetime
// observation: Done closes when the session ends for ANY reason, and Err
// reports the cause once it has.
type TunnelSession struct {
	net.Conn
	sess *clientSession
	done chan struct{}

	errMu sync.Mutex
	err   error
}

func newTunnelSession(conn net.Conn, sess *clientSession) *TunnelSession {
	ts := &TunnelSession{Conn: conn, sess: sess, done: make(chan struct{})}
	go func() {
		<-sess.closeChan
		sess.closeReasonMu.Lock()
		reason := sess.closeReason
		sess.closeReasonMu.Unlock()
		ts.errMu.Lock()
		if reason == "" {
			ts.err = ErrTunnelClosed
		} else {
			ts.err = fmt.Errorf("%w: %s", ErrTunnelClosed, reason)
		}
		ts.errMu.Unlock()
		close(ts.done)
	}()
	return ts
}

// Done is closed when the tunnel session ends.
func (t *TunnelSession) Done() <-chan struct{} { return t.done }

// Err returns the reason the session ended, or nil while it is alive. Valid
// only after Done is closed.
func (t *TunnelSession) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.err
}

// ClientStats is a point-in-time snapshot of a Client's live state.
type ClientStats struct {
	Sessions int // live tunnels (gauge)
}

// Stats returns a snapshot of the client's live state.
func (c *Client) Stats() ClientStats {
	st := ClientStats{}
	c.sessions.Range(func(_, _ any) bool {
		st.Sessions++
		return true
	})
	return st
}

// Close stops the client and tears down every tunnel.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)
		close(c.closeChan)
		c.sessions.Range(func(_, v any) bool {
			if s, ok := v.(*clientSession); ok {
				s.close()
			}
			return true
		})
		_ = c.tr.Close()
		c.logInfo("[Client] stopped")
		c.events.close()
	})
}

// ----- clientSession -----

type clientSession struct {
	client *Client
	sid    uint32
	conn   net.Conn // local application connection

	frameKeys *FrameKeys

	// granted is the endpoint the server echoed in the handshake ACK ("" = the
	// server's default target). Exposed through DialOptions.OnGranted.
	granted string

	sendPacketNo uint64
	sendSeq      uint64
	recvSeq      uint64
	replayFilter ReplayFilter

	recvQueue map[uint64][]byte
	recvMu    sync.Mutex

	unacked     map[uint64]*unackedPkt
	unackedMu   sync.Mutex
	unackedCond *sync.Cond

	rttEst *rttEstimator

	lastActive time.Time
	lastSent   time.Time
	mu         sync.Mutex

	// Request-window accounting for request-driven carriers: how many requests
	// we have emitted and how many answers we have seen. The difference is the
	// in-flight window.
	pollMu      sync.Mutex
	poked       uint64
	answered    uint64
	windowStart time.Time

	closeOnce     sync.Once
	closeChan     chan struct{}
	closed        int32
	closeReason   string
	closeReasonMu sync.Mutex
}

func (s *clientSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *clientSession) isClosed() bool { return atomic.LoadInt32(&s.closed) == 1 }

// closeWithReason closes the session and records WHY, for TunnelSession.Err().
func (s *clientSession) closeWithReason(reason string) {
	if reason == "" {
		reason = "closed"
	}
	s.closeReasonMu.Lock()
	if s.closeReason == "" {
		s.closeReason = reason // first writer wins: the root cause
	}
	s.closeReasonMu.Unlock()
	s.close()
}

func (s *clientSession) close() {
	s.closeOnce.Do(func() {
		atomic.StoreInt32(&s.closed, 1)
		s.unackedMu.Lock()
		if s.unackedCond != nil {
			s.unackedCond.Broadcast()
		}
		s.unackedMu.Unlock()
		close(s.closeChan)
		if s.conn != nil {
			// Tell the server to tear the session down; best effort.
			fin := &Record{Magic: s.client.magic, Version: Version, Cmd: CmdFin, SessionID: s.sid}
			s.sendControl(fin, s.poke)
			s.conn.Close()
		}
	})
}

// poke transmits one client→server record. On a request-driven carrier it is an
// Echo Request and the answer arrives as its Echo Reply; the emission is
// counted so the poll loop knows how many requests are outstanding.
func (s *clientSession) poke(wire []byte) error {
	p := pollerOf(s.client.tr)
	if p == nil {
		return s.client.tr.WriteRecord(wire, s.client.serverAddr)
	}
	if _, err := p.Poke(wire, s.client.serverAddr); err != nil {
		return err
	}
	s.pollMu.Lock()
	s.poked++
	if s.poked-s.answered == 1 {
		s.windowStart = time.Now()
	}
	s.pollMu.Unlock()
	return nil
}

// noteAnswered records that one carrier answer arrived, freeing window space.
func (s *clientSession) noteAnswered() {
	s.pollMu.Lock()
	s.answered++
	s.pollMu.Unlock()
}

// localToRemote streams the local application's bytes into the tunnel.
func (s *clientSession) localToRemote() {
	bufSize := s.client.maxPayload
	if bufSize <= 0 {
		bufSize = MaxPayloadLen
	}
	buf := make([]byte, bufSize)
	// A short read deadline keeps a half-closed connection from pinning the
	// session forever; a timeout is the marker for "no data right now".
	var deadline time.Time
	for {
		if s.isClosed() {
			return
		}
		if now := time.Now(); !now.Before(deadline) {
			deadline = now.Add(time.Second)
			_ = s.conn.SetReadDeadline(deadline)
		}
		// The local end is always a byte stream (net.Pipe), so chunking the
		// read to the carrier's live budget is safe and is what makes an
		// adaptive MTU visible on the wire. Re-read it each iteration.
		limit := bufSize
		if budget := s.client.sendPayloadBudget(); budget > 0 && budget < limit {
			limit = budget
		}
		n, err := s.conn.Read(buf[:limit])
		if n > 0 {
			if serr := s.sendData(buf[:n]); serr != nil {
				if !s.isClosed() {
					s.client.logWarn("[Client] [Session 0x%08X] send failed: %v", s.sid, serr)
				}
				s.closeWithReason("tunnel send failed")
				return
			}
			s.mu.Lock()
			s.lastSent = time.Now()
			s.mu.Unlock()
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.closeWithReason("local conn read failed")
			return
		}
	}
}

// sendData assigns a sequence number, records the record for retransmission and
// pushes it out. It blocks while the send window is full (backpressure).
func (s *clientSession) sendData(payload []byte) error {
	if s.isClosed() {
		return ErrClosed
	}
	if len(payload) > s.client.maxPayload {
		return fmt.Errorf("payload of %d bytes exceeds the carrier payload budget (%d): chunk writes to %d bytes or smaller",
			len(payload), s.client.maxPayload, s.client.maxPayload)
	}

	s.unackedMu.Lock()
	for len(s.unacked) >= s.client.cfg.SendWindow && !s.isClosed() {
		s.unackedCond.Wait()
	}
	s.unackedMu.Unlock()
	if s.isClosed() {
		return ErrClosed
	}

	seq := atomic.AddUint64(&s.sendSeq, 1) - 1
	rec := &Record{
		Magic: s.client.magic, Version: Version, Cmd: CmdData,
		SessionID: s.sid, Seq: seq, Ack: s.currentAck(), Data: payload,
	}
	encoded := s.encodeRecord(rec)
	if len(encoded) == 0 {
		return errors.New("failed to seal DATA record")
	}

	rto := s.rttEst.RTO()
	s.unackedMu.Lock()
	now := time.Now()
	s.unacked[seq] = &unackedPkt{wire: encoded, firstSent: now, sentTime: now, rto: rto}
	s.unackedMu.Unlock()

	// A carrier write failure during a route transition is equivalent to packet
	// loss: the retained record is retried by retransmitLoop, so tearing the
	// session down here would defeat that machinery.
	if err := s.poke(encoded); err != nil {
		s.client.logWarn("[Client] [Session 0x%08X] initial DATA send deferred to retransmit loop: %v", s.sid, err)
	}
	return nil
}

func (s *clientSession) handleAck(ackSeq uint64) {
	s.unackedMu.Lock()
	// Cumulative, mirroring the server: everything up to ackSeq is delivered.
	if pkt, ok := s.unacked[ackSeq]; ok && pkt.retries == 0 {
		s.rttEst.Sample(time.Since(pkt.firstSent))
	}
	// Feed the carrier the wire size of every record this ACK retires. Only
	// never-retransmitted records count: a retransmitted one proves the path is
	// marginal at that size, not that it is roomy.
	fed := s.client.mtuFed
	for seq, pkt := range s.unacked {
		if seq <= ackSeq {
			if fed != nil && pkt.retries == 0 {
				fed.RecordAcked(len(pkt.wire))
			}
			delete(s.unacked, seq)
		}
	}
	s.unackedMu.Unlock()
	if s.unackedCond != nil {
		s.unackedCond.Broadcast()
	}
}

func (s *clientSession) retransmitLoop() {
	ticker := time.NewTicker(clientRetransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			// The carrier may declare a floor well above the estimator's RTO: a
			// throttled path cannot answer faster than its own pace, and a
			// blocked one must not be probed faster than its block timeout, or
			// every retransmit is more fuel on the fire that is rate-limiting
			// us. Re-read each tick because it moves with the classification.
			floor := rtoFloorOf(s.client.tr)
			fed := s.client.mtuFed
			s.unackedMu.Lock()
			for seq, pkt := range s.unacked {
				wait := pkt.rto
				if wait < floor {
					wait = floor
				}
				if now.Sub(pkt.sentTime) < wait {
					continue
				}
				pkt.retries++
				if pkt.retries > clientMaxRetries {
					s.client.logWarn("[Client] [Session 0x%08X] Seq %d abandoned after %d retries", s.sid, seq, pkt.retries)
					if fed != nil {
						// Evidence for in-band MTU adaptation: this record
						// exhausted its retransmissions at that size.
						fed.RecordLost(len(pkt.wire))
					}
					s.unackedMu.Unlock()
					s.closeWithReason("max retransmits exceeded")
					return
				}
				pkt.sentTime = now
				pkt.rto = minDuration(pkt.rto*3/2, 10*time.Second)
				_ = s.poke(pkt.wire)
			}
			s.unackedMu.Unlock()

			s.mu.Lock()
			idle := now.Sub(s.lastActive)
			s.mu.Unlock()
			if idle > clientRecvTimeout {
				s.client.logWarn("[Client] [Session 0x%08X] idle timeout (%v)", s.sid, idle)
				s.closeWithReason("idle timeout")
				return
			}
		}
	}
}

// keepAliveLoop emits a PING when the tunnel has been quiet. It only runs for
// datagram carriers: on a request-driven carrier the poll loop subsumes it.
func (s *clientSession) keepAliveLoop() {
	if pollerOf(s.client.tr) != nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			s.mu.Lock()
			sinceSend := time.Since(s.lastSent)
			s.mu.Unlock()
			if sinceSend < s.client.cfg.keepAlive() {
				continue
			}
			ping := &Record{
				Magic: s.client.magic, Version: Version, Cmd: CmdPing,
				SessionID: s.sid, Ack: s.currentAck(),
			}
			s.sendControl(ping, s.poke)
			s.mu.Lock()
			s.lastSent = time.Now()
			s.mu.Unlock()
		}
	}
}

// pollLoop keeps a small window of requests in flight on a request-driven
// carrier. It is the ONLY way downlink can flow over ICMP, and its window size
// is the hard ceiling on throughput (~ W / RTT, further bounded by the
// carrier's pace). The poll spacing adapts: pace while active, idle_poll_ms
// when quiet, keepalive_ms when deeply idle.
func (s *clientSession) pollLoop() {
	if pollerOf(s.client.tr) == nil {
		return
	}
	cfg := s.client.cfg
	for {
		if s.isClosed() {
			return
		}
		s.mu.Lock()
		idleFor := time.Since(s.lastActive)
		s.mu.Unlock()

		interval := cfg.pollInterval()
		switch {
		case idleFor >= cfg.keepAlive():
			interval = cfg.keepAlive()
		case idleFor >= cfg.idlePoll():
			interval = cfg.idlePoll()
		}
		timer := time.NewTimer(interval)
		select {
		case <-s.closeChan:
			timer.Stop()
			return
		case <-timer.C:
		}
		if s.isClosed() {
			return
		}
		s.maybePoll(3 * cfg.idlePoll())
	}
}

// maybePoll sends one poll if the request window has room, or if the window has
// been stalled long enough that its requests must be presumed lost (otherwise a
// fully black-holed window would stop polling forever and never recover).
func (s *clientSession) maybePoll(stall time.Duration) {
	s.pollMu.Lock()
	if outstanding := s.poked - s.answered; int(outstanding) >= s.client.cfg.pollsInFlight() {
		if time.Since(s.windowStart) < stall {
			s.pollMu.Unlock()
			return
		}
		// Refill: treat the stalled in-flight requests as lost.
		s.poked = s.answered
		s.windowStart = time.Now()
	}
	if s.poked == s.answered {
		s.windowStart = time.Now()
	}
	s.poked++
	s.pollMu.Unlock()

	ping := &Record{
		Magic: s.client.magic, Version: Version, Cmd: CmdPing,
		SessionID: s.sid, Ack: s.currentAck(),
	}
	s.sendControl(ping, s.poke)
}

// handleData delivers server data to the local application, buffering
// out-of-order records and ACKing every record it delivers.
func (s *clientSession) handleData(rec *Record) bool {
	if rec.Seq == 0 {
		return true
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	payload := rec.Data
	expected := atomic.LoadUint64(&s.recvSeq)
	if rec.Seq != expected {
		if rec.Seq < expected {
			// Already delivered: the server is retransmitting because it lost
			// our ACK, so re-ACK instead of dropping it.
			s.sendACK(expected - 1)
			return true
		}
		if _, dup := s.recvQueue[rec.Seq]; dup {
			return true
		}
		if len(s.recvQueue) >= 512 {
			return false
		}
		s.recvQueue[rec.Seq] = append([]byte(nil), payload...)
		s.touch()
		return true
	}
	s.touch()

	type pending struct {
		seq     uint64
		payload []byte
	}
	run := []pending{{seq: expected, payload: payload}}
	next := expected + 1
	for {
		raw, ok := s.recvQueue[next]
		if !ok {
			break
		}
		delete(s.recvQueue, next)
		run = append(run, pending{seq: next, payload: raw})
		next++
	}

	delivered := uint64(0)
	for _, p := range run {
		if err := writeAll(s.conn, p.payload); err != nil {
			s.closeWithReason("application write failed")
			return true
		}
		delivered++
	}
	if delivered > 0 {
		atomic.StoreUint64(&s.recvSeq, expected+delivered)
		s.sendACK(expected + delivered - 1)
	}
	return true
}

// sendACK acknowledges everything up to ackSeq. Sent once per delivered record
// and again whenever a duplicate shows up (its original ACK was lost), so the
// server can stop retransmitting.
func (s *clientSession) sendACK(ackSeq uint64) {
	ack := &Record{
		Magic: s.client.magic, Version: Version, Cmd: CmdAck,
		SessionID: s.sid, Ack: ackSeq, WindowSize: 65535,
	}
	s.sendControl(ack, s.poke)
}

// sendControl seals a control record and hands it to send. Returns false when
// the session lacks record protection or the packet-number space is exhausted.
func (s *clientSession) sendControl(r *Record, send func([]byte) error) bool {
	r.PacketNo = atomic.AddUint64(&s.sendPacketNo, 1)
	if r.PacketNo == 0 || s.frameKeys == nil {
		return false
	}
	wire := SealRecordAEAD(r, s.frameKeys.Send, r.Data, s.client.maxRecordSize)
	if len(wire) == 0 {
		return false
	}
	if err := send(wire); err != nil && !s.isClosed() {
		s.client.logWarn("[Client] [Session 0x%08X] send control failed: %v", s.sid, err)
	}
	return true
}

func (s *clientSession) currentAck() uint64 {
	if next := atomic.LoadUint64(&s.recvSeq); next > 0 {
		return next - 1
	}
	return 0
}

func (s *clientSession) reackDuplicateData() {
	if ack := s.currentAck(); ack > 0 {
		s.sendACK(ack)
	}
}

// encodeRecord assigns a fresh packet number and seals the record.
func (s *clientSession) encodeRecord(r *Record) []byte {
	r.PacketNo = atomic.AddUint64(&s.sendPacketNo, 1)
	if r.PacketNo == 0 || s.frameKeys == nil {
		return nil
	}
	return SealRecordAEAD(r, s.frameKeys.Send, r.Data, s.client.maxRecordSize)
}
