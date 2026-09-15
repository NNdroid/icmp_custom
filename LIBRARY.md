# icmp_custom library API (embedder guide)

`github.com/NNdroid/icmp_custom/tunnel` is a Go library that can be embedded
directly. This document covers only the public API; runnable,
`tunnel/example`-style samples live in `tunnel/library_example_test.go` (an
external test package that uses only the exported surface, so it doubles as a
wiring template).

## 1. Five-minute integration

```go
import "github.com/NNdroid/icmp_custom/tunnel"

// Server: ICMP carrier + default forwarding dialer (Linux, needs CAP_NET_RAW)
srv, err := tunnel.NewServer(tunnel.ServerConfig{
    TargetAddr: "tcp://127.0.0.1:8080",
    Passwords:  []string{"psk"},
})
go srv.Start()

// Client
cli, err := tunnel.NewClient(tunnel.ClientConfig{
    ServerAddr: "203.0.113.7",
    Passwords:  []string{"psk"},
})
conn, err := cli.DialTunnel(ctx, tunnel.DialOptions{Target: "tcp://10.0.0.5:22"})
// conn is a net.Conn; read and write it directly
```

## 2. Injected construction (the library's core shape)

When you do not open the ICMP socket yourself, every component is injectable:

| Constructor | Injection point | Purpose |
|---|---|---|
| `NewServerWithTransport(cfg, tr, dial)` | `tunnel.Transport` + `TargetDialer` | your own carrier + your own forwarding channel |
| `NewClientWithTransport(cfg, tr)` | `tunnel.Transport` | your own carrier |
| `NewServerWithDialer(cfg, dial)` | `TargetDialer` | ICMP carrier + custom forwarding |
| `NewServer(cfg)` / `NewClient(cfg)` | — | pure config, ICMP carrier |

**DialContext injection**: `TargetDialer` is
`func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error)`.
Every dial to a forwarding target goes through it, so backend connections can be
routed through any `net.Dialer` (with a `Control` hook, interface binding,
fwmark, proxy, and so on):

```go
var d net.Dialer{
    Control: func(network, address string, c syscall.RawConn) { /* protect / bind */ },
}
srv, _ := tunnel.NewServerWithTransport(cfg, tr,
    func(ctx context.Context, sid uint32, network, address string) (net.Conn, error) {
        return d.DialContext(ctx, network, address)
    })
```

The `Transport` interface (5 methods + 2 marker capabilities) is the carrier
seam; the in-memory queue, ICMP, and any future UDP carrier all implement it.
See `tunnel/transport.go` for the signatures.

## 3. Protect (Android VpnService exemption)

```go
cli, err := tunnel.NewClient(tunnel.ClientConfig{
    ServerAddr: "203.0.113.7",
    Passwords:  []string{"psk"},
    // Called on each ICMP carrier socket after it is created and before the
    // first packet leaves; invoke VpnService.protect(fd) here, or the Echo
    // traffic is captured by the app's own tunnel and loops back on itself.
    ProtectFD: func(fd int) error { return protect(fd) },
})
```

- The Android build (`GOOS=android`) uses the unprivileged ping socket
  (`SOCK_DGRAM` + `IPPROTO_ICMP[v6]`): the kernel owns the IP header, the
  checksum, and the Echo Identifier.
- A startup self-check reads `net.ipv4.ping_group_range`: when it does not
  admit this app's gid/fsgid, construction fails immediately with
  `ErrPingSocketDenied` and the fix command in the message.
- The Linux raw-socket carrier also calls `ProtectFD` (a no-op on desktop
  Linux).
- When you inject your own `Transport`, protect is the embedder's
  responsibility (you opened the socket).

## 4. Logging interface and global level

```go
// Inject your own Logger (concurrency requirements are in the interface doc)
srv, _ := tunnel.NewServerWithTransport(cfg, tr, dial)
cfg.Logger = myLogger   // ServerConfig.Logger / ClientConfig.Logger

// Or use the global level knob: any component with neither log_level set nor a
// Logger injected follows it
tunnel.SetGlobalLogLevel(tunnel.LogLevelDebug)   // enable global debug
defer tunnel.SetGlobalLogLevel(tunnel.LogLevelInfo)
```

Precedence (highest first):

1. an injected `Logger` (full takeover; `Nop{}` silences it);
2. the config's `log_level` (debug|info|warn|error, default info);
3. the global default set by `SetGlobalLogLevel` (default info).

`stdLogger` emits lines like `[DEBUG] [Client] ...`, with the level column
padded to a fixed 5 characters so they line up under grep. Hot paths (the pacer,
the retransmit timers) pre-check with `levelOf` to skip formatting, so an
injected Logger's `Debugf` is only actually called when debug is on.

## 5. Lifecycle / events / stats

```go
srv.SetEventHandler(func(ev tunnel.SessionEvent) { ... })   // established/closed/auth-rejected/replay-dropped/target-denied
cli.SetEventHandler(func(ev tunnel.ClientEvent) { ... })    // established/died/reconnecting/handshake-retrying
srv.EventsDropped(); cli.EventsDropped()                    // slow-handler drop counter
srv.Stats()                                                 // sessions/security counters, point-in-time snapshot
cli.PollSchedule()                                          // the resolved poll cadence
cli.NewAutoReconnect(dialOpts, onGranted)                   // a net.Conn that re-dials on disconnect
```

## 6. Platform matrix

| Platform | Carrier | Role | Privilege |
|---|---|---|---|
| Linux | `SOCK_RAW` ICMPv4+v6 (dual-stack) | server + client | CAP_NET_RAW |
| Android | ping socket (unprivileged) | client | ping_group_range |
| Windows / macOS / others | explicit refusal (`ErrTransportUnsupported`) | — | — |

All errors are matchable sentinels: `ErrConfigRequired`,
`ErrTransportUnsupported`, `ErrNoCapNetRaw`, `ErrPingSocketDenied`,
`ErrHandshakeTimeout`, `ErrClosed`, `ErrNoRoute`, `ErrRecordTooLarge`,
`ErrNonceCollision`.
