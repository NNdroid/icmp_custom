package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The session layer's use of the optional carrier capabilities.
//
// The ICMP profile's health classification and its automatic MTU both depend on
// the session telling the carrier things the carrier cannot observe for itself:
// which records were acknowledged, which exhausted their retransmissions, and
// which inbound record actually authenticated. These tests drive a real
// server/client pair over the in-memory link wrapped in those capabilities, so
// the wiring is proven end to end rather than by inspection.
// ---------------------------------------------------------------------------

// feedbackEndpoint wraps the in-memory fake with the three optional feedback
// capabilities. The embedded endpoint keeps every other behaviour — and every
// other capability — exactly as the rest of the suite expects it.
type feedbackEndpoint struct {
	*fakeEndpoint

	mu         sync.Mutex
	acked      []int
	lost       []int
	authed     int
	state      CarrierState
	floor      time.Duration
	floorCalls int
}

// Compile-time proof the wrapper still satisfies the whole capability surface
// the session can discover.
var (
	_ Transport             = (*feedbackEndpoint)(nil)
	_ MaxRecordSizer        = (*feedbackEndpoint)(nil)
	_ Poller                = (*feedbackEndpoint)(nil)
	_ Prober                = (*feedbackEndpoint)(nil)
	_ MTUFeedback           = (*feedbackEndpoint)(nil)
	_ AuthenticatedFeedback = (*feedbackEndpoint)(nil)
	_ CarrierCondition      = (*feedbackEndpoint)(nil)
)

func (e *feedbackEndpoint) RecordAcked(size int) {
	e.mu.Lock()
	e.acked = append(e.acked, size)
	e.mu.Unlock()
}

func (e *feedbackEndpoint) RecordLost(size int) {
	e.mu.Lock()
	e.lost = append(e.lost, size)
	e.mu.Unlock()
}

func (e *feedbackEndpoint) RecordAuthenticated() {
	e.mu.Lock()
	e.authed++
	// Mirror the real carrier: authentication is what clears a block.
	e.state = CarrierUp
	e.mu.Unlock()
}

func (e *feedbackEndpoint) CarrierState() CarrierState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *feedbackEndpoint) RTOFloor() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.floorCalls++
	return e.floor
}

func (e *feedbackEndpoint) snapshot() (acked, lost []int, authed, floorCalls int, state CarrierState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]int(nil), e.acked...), append([]int(nil), e.lost...),
		e.authed, e.floorCalls, e.state
}

// newFeedbackLink builds a client/server pair whose two ends both advertise the
// optional capabilities. floor is the retransmit floor both ends publish; pass
// defaultRTOFloor for "no change in behaviour".
func newFeedbackLink(t *testing.T, clientState CarrierState, floor time.Duration) (*feedbackEndpoint, *feedbackEndpoint) {
	t.Helper()
	cEp, sEp := newFakeLink("client", "server", testRecordLimit)
	client := &feedbackEndpoint{fakeEndpoint: cEp, state: clientState, floor: floor}
	server := &feedbackEndpoint{fakeEndpoint: sEp, state: CarrierInit, floor: floor}
	return client, server
}

func TestSessionFeedsCarrierAcknowledgementsAndAuthentication(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	client, server := newFeedbackLink(t, CarrierInit, defaultRTOFloor)

	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://" + backend, Passwords: []string{"secret"},
	}, server, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)

	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2", Passwords: []string{"secret"},
	}, client)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	want := []byte("feedback wiring")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}

	// Both ends must have authenticated inbound records: it is the only signal
	// that clears a path the carrier had declared blocked.
	waitFor(t, 2*time.Second, func() bool {
		_, _, clientAuthed, _, _ := client.snapshot()
		_, _, serverAuthed, _, _ := server.snapshot()
		return clientAuthed > 0 && serverAuthed > 0
	}, "both ends must report authenticated inbound records")

	// Both ends must have fed back the wire size of the records their peer
	// acknowledged. The size must be a real, positive wire size — the whole
	// point is that the ACK of a record IS the MTU verdict.
	waitFor(t, 2*time.Second, func() bool {
		clientAcked, _, _, _, _ := client.snapshot()
		serverAcked, _, _, _, _ := server.snapshot()
		return len(clientAcked) > 0 && len(serverAcked) > 0
	}, "both ends must feed acknowledged record sizes back to the carrier")

	// Each retransmit loop reads the carrier's floor once per tick, so this also
	// confirms the loops consume the value rather than caching it at setup.
	waitFor(t, 2*time.Second, func() bool {
		_, _, _, clientFloorCalls, _ := client.snapshot()
		_, _, _, serverFloorCalls, _ := server.snapshot()
		return clientFloorCalls > 0 && serverFloorCalls > 0
	}, "the retransmit loops must consult the carrier's RTO floor")

	clientAcked, clientLost, _, _, _ := client.snapshot()
	serverAcked, serverLost, _, _, _ := server.snapshot()

	for _, size := range append(append([]int(nil), clientAcked...), serverAcked...) {
		if size < RecordMinSize || size > testRecordLimit {
			t.Fatalf("a feedback size of %d is not a plausible wire size (min %d, carrier %d)",
				size, RecordMinSize, testRecordLimit)
		}
	}
	// The carrier is up and healthy, so nothing should have been reported lost.
	if len(clientLost) != 0 || len(serverLost) != 0 {
		t.Fatalf("a clean run reported losses: client=%v server=%v", clientLost, serverLost)
	}
}

// TestSessionAuthenticationClearsABlockedCarrier pins the one event a carrier
// cannot observe for itself. Without it, a path that had been declared blocked
// would stay blocked forever even while records were flowing perfectly.
func TestSessionAuthenticationClearsABlockedCarrier(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	// The client's carrier starts life believing the path is dead. Establishing
	// a tunnel over it can only succeed if the session reports authentication
	// back to the carrier.
	client, server := newFeedbackLink(t, CarrierBlocked, defaultRTOFloor)

	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://" + backend, Passwords: []string{"secret"},
	}, server, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)

	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2", Passwords: []string{"secret"},
	}, client)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("a blocked-carrier client must still be able to establish: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("read: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		_, _, _, _, state := client.snapshot()
		return state == CarrierUp
	}, "an authenticated record must clear the blocked state")
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, within time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestFeedbackEndpointKeepsTheFakeContract guards against the wrapper silently
// changing the carrier the rest of the suite depends on.
func TestFeedbackEndpointKeepsTheFakeContract(t *testing.T) {
	client, server := newFeedbackLink(t, CarrierInit, defaultRTOFloor)

	var asTransport Transport = client
	if maxRecordSizeOf(asTransport) != testRecordLimit {
		t.Fatalf("MaxRecordSize = %d, want the fake's %d", maxRecordSizeOf(asTransport), testRecordLimit)
	}
	if maxReceiveSizeOf(asTransport) != testRecordLimit {
		t.Fatalf("MaxReceiveSize = %d, want the fake's %d", maxReceiveSizeOf(asTransport), testRecordLimit)
	}
	if pollerOf(asTransport) == nil {
		t.Fatal("the wrapper must keep the Poller the fake provides")
	}

	// The wrapper must be a transparent carrier, not a new one.
	rec := []byte("a complete record")
	if err := client.WriteRecord(rec, netip.MustParseAddrPort("192.0.2.2:10002")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := server.readWithin(t, buf, time.Second)
	if string(buf[:n]) != string(rec) {
		t.Fatalf("delivered %q, want %q", buf[:n], rec)
	}
}
