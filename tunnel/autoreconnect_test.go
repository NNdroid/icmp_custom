package tunnel

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestAutoReconnectDialsLazilyAndRoundTrips(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, srv := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ar := NewAutoReconnect(cli, DialOptions{}, nil)
	t.Cleanup(func() { _ = ar.Close() })

	// Constructing the wrapper must not dial anything: the first tunnel is
	// created on first use.
	if got := srv.Stats().Sessions; got != 0 {
		t.Fatalf("sessions after NewAutoReconnect = %d, want 0", got)
	}
	if ar.RestartCount() != 0 {
		t.Fatalf("RestartCount = %d, want 0", ar.RestartCount())
	}

	if err := ar.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []byte("ping")
	if _, err := ar.Write(want); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(ar, got); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}
	if n := srv.Stats().Sessions; n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}
}

func TestAutoReconnectRepairsAfterReadFailure(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, srv := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)

	reconnecting := make(chan ClientEvent, 4)
	cli.SetEventHandler(func(ev ClientEvent) {
		if ev.Kind == Reconnecting {
			reconnecting <- ev
		}
	})

	granted := make(chan string, 4)
	ar := NewAutoReconnect(cli, DialOptions{}, func(g string) { granted <- g })
	t.Cleanup(func() { _ = ar.Close() })

	if err := ar.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ar.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("first"))
	if _, err := io.ReadFull(ar, got); err != nil {
		t.Fatal(err)
	}

	select {
	case <-granted:
	case <-time.After(2 * time.Second):
		t.Fatal("onGranted was not invoked for the initial dial")
	}

	// Force an IO failure on the live tunnel: a read that hits its deadline.
	// The wrapper must drop the session so the NEXT operation re-dials.
	if err := ar.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := ar.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the read to time out on an idle tunnel")
	}

	// The replacement tunnel is dialed transparently by the next write.
	if err := ar.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ar.Write([]byte("second")); err != nil {
		t.Fatalf("Write after failure: %v", err)
	}
	got2 := make([]byte, len("second"))
	if _, err := io.ReadFull(ar, got2); err != nil {
		t.Fatalf("Read after reconnect: %v", err)
	}
	if string(got2) != "second" {
		t.Fatalf("echo after reconnect = %q, want %q", got2, "second")
	}

	if n := ar.RestartCount(); n != 1 {
		t.Fatalf("RestartCount = %d, want 1", n)
	}
	select {
	case ev := <-reconnecting:
		if ev.Attempt < 1 {
			t.Fatalf("Reconnecting attempt = %d, want >= 1", ev.Attempt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no Reconnecting event was emitted")
	}
	select {
	case <-granted:
	case <-time.After(2 * time.Second):
		t.Fatal("onGranted was not invoked again for the replacement tunnel")
	}
	// The torn-down session is retired; exactly one live session remains.
	deadline := time.Now().Add(3 * time.Second)
	for srv.Stats().Sessions != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := srv.Stats().Sessions; n != 1 {
		t.Fatalf("live sessions = %d, want 1 after reconnect", n)
	}
}

func TestAutoReconnectCloseRefusesFurtherOps(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ar := NewAutoReconnect(cli, DialOptions{}, nil)
	if err := ar.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent.
	if err := ar.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := ar.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close: err = %v, want ErrClosed", err)
	}
	if _, err := ar.Read(make([]byte, 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Read after Close: err = %v, want ErrClosed", err)
	}
	// Addresses are reportable even before any tunnel exists.
	if ar.LocalAddr() == nil || ar.RemoteAddr() == nil {
		t.Fatal("Addr methods must never return nil")
	}
}
