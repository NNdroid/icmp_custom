package tunnel

import (
	"context"
	"testing"
	"time"
)

func TestScratchHandshakeRig(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	for _, tc := range []struct {
		name    string
		backoff time.Duration
	}{
		{"backoff-1ms", time.Millisecond},
		{"backoff-50ms", 50 * time.Millisecond},
		{"backoff-400ms", 400 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cEp, _, _ := newTestServer(t, ServerConfig{
				TargetAddr: "tcp://" + backend,
				Passwords:  []string{"bench-psk"},
				Logger:     Nop{},
			}, nil)
			cli := newTestClient(t, ClientConfig{
				ServerAddr:        "192.0.2.2",
				Passwords:         []string{"bench-psk"},
				Logger:            Nop{},
				HandshakeBackoff:  tc.backoff,
				HandshakeAttempts: 20,
			}, cEp)

			for i := 0; i < 5; i++ {
				start := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				conn, err := cli.DialTunnel(ctx, DialOptions{})
				cancel()
				if err != nil {
					t.Fatalf("iter %d: DialTunnel after %v: %v", i, time.Since(start), err)
				}
				t.Logf("iter %d: %v", i, time.Since(start))
				_ = conn.Close()
			}
		})
	}
}
