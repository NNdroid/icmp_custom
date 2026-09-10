# icmp_custom 类库 API（embedder 指南）

`github.com/NNdroid/icmp_custom/tunnel` 是可直接嵌入的 Go 类库。本文只讲公开 API；
`tunnel/example` 风格的可运行示例见 `tunnel/library_example_test.go`（外部测试包，
仅使用导出接口，可作为接入代码模板）。

## 1. 五分钟接入

```go
import "github.com/NNdroid/icmp_custom/tunnel"

// 服务端：ICMP 载体 + 默认转发 dialer（Linux，需要 CAP_NET_RAW）
srv, err := tunnel.NewServer(tunnel.ServerConfig{
    TargetAddr: "tcp://127.0.0.1:8080",
    Passwords:  []string{"psk"},
})
go srv.Start()

// 客户端
cli, err := tunnel.NewClient(tunnel.ClientConfig{
    ServerAddr: "203.0.113.7",
    Passwords:  []string{"psk"},
})
conn, err := cli.DialTunnel(ctx, tunnel.DialOptions{Target: "tcp://10.0.0.5:22"})
// conn 是 net.Conn，直接读写即可
```

## 2. 注入式构造（类库的核心形态）

不自己开 ICMP socket 时，全部组件都可注入：

| 构造函数 | 注入点 | 用途 |
|---|---|---|
| `NewServerWithTransport(cfg, tr, dial)` | `tunnel.Transport` + `TargetDialer` | 自有载体 + 自有转发通道 |
| `NewClientWithTransport(cfg, tr)` | `tunnel.Transport` | 自有载体 |
| `NewServerWithDialer(cfg, dial)` | `TargetDialer` | ICMP 载体 + 自定义转发 |
| `NewServer(cfg)` / `NewClient(cfg)` | — | 纯配置，ICMP 载体 |

**DialContext 注入**：`TargetDialer` 即
`func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error)`。
转发目标的所有拨号都经过它，可以把后端连接路由到任意
`net.Dialer`（含 `Control` 钩子、绑网卡、fwmark、代理等）：

```go
var d net.Dialer{
    Control: func(network, address string, c syscall.RawConn) { /* protect / bind */ },
}
srv, _ := tunnel.NewServerWithTransport(cfg, tr,
    func(ctx context.Context, sid uint32, network, address string) (net.Conn, error) {
        return d.DialContext(ctx, network, address)
    })
```

`Transport` 接口（5 个方法 + 2 个标签）是载体接缝；内存队列、ICMP、
未来 UDP 载体都实现它。签名见 `tunnel/transport.go`。

## 3. Protect（Android VpnService 豁免）

```go
cli, err := tunnel.NewClient(tunnel.ClientConfig{
    ServerAddr: "203.0.113.7",
    Passwords:  []string{"psk"},
    // 每个 ICMP 载体 socket 创建后、首包发出前回调；在此调用
    // VpnService.protect(fd)，否则 Echo 流量会被自己的 VPN 捕获形成回环。
    ProtectFD: func(fd int) error { return protect(fd) },
})
```

- Android 构建（`GOOS=android`）使用免特权 ping socket（`SOCK_DGRAM` +
  `IPPROTO_ICMP[v6]`）：内核负责 IP 头、校验和与 Echo Identifier。
- 启动自检 `net.ipv4.ping_group_range`：不含本应用 gid/fsgid 时，
  构造阶段直接报 `ErrPingSocketDenied` 并给出修复命令。
- Linux 原始 socket 载体同样回调 `ProtectFD`（桌面 Linux 为 no-op）。
- 注入自有 `Transport` 时 protect 由嵌入者自理（socket 是你开的）。

## 4. 日志接口与全局级别

```go
// 注入自有 Logger（并发安全要求见接口注释）
srv, _ := tunnel.NewServerWithTransport(cfg, tr, dial)
cfg.Logger = myLogger   // ServerConfig.Logger / ClientConfig.Logger

// 或使用全局级别旋钮：未配置 log_level、未注入 Logger 的组件全部跟随它
tunnel.SetGlobalLogLevel(tunnel.LogLevelDebug)   // 打开全局 debug
defer tunnel.SetGlobalLogLevel(tunnel.LogLevelInfo)
```

级别优先级（高→低）：

1. 注入的 `Logger`（完全接管，`Nop{}` 静音）；
2. 配置里的 `log_level`（debug|info|warn|error，缺省 info）；
3. `SetGlobalLogLevel` 设置的全局默认（缺省 info）。

`stdLogger` 输出形如 `[DEBUG] [Client] ...`，级别列固定 5 字符对齐，
便于 grep。热路径（pacer、重传计时）用 `levelOf` 预判跳过格式化，
注入 Logger 时 `Debugf` 才会真正被调用。

## 5. 生命周期 / 事件 / 统计

```go
srv.SetEventHandler(func(ev tunnel.SessionEvent) { ... })   // established/closed/auth-rejected/replay-dropped/target-denied
cli.SetEventHandler(func(ev tunnel.ClientEvent) { ... })    // established/died/reconnecting/handshake-retrying
srv.EventsDropped(); cli.EventsDropped()                    // 慢 handler 丢弃计数
srv.Stats()                                                 // 会话/安全计数快照
cli.PollSchedule()                                          // 解析后的 poll 节奏
cli.NewAutoReconnect(dialOpts, onGranted)                   // 断线自动重连的 net.Conn
```

## 6. 平台矩阵

| 平台 | 载体 | 角色 | 权限 |
|---|---|---|---|
| Linux | `SOCK_RAW` ICMPv4+v6（双栈） | 服务端 + 客户端 | CAP_NET_RAW |
| Android | ping socket（免特权） | 客户端 | ping_group_range |
| Windows / macOS / 其他 | 显式拒绝（`ErrTransportUnsupported`） | — | — |

错误均为可匹配的 sentinel：`ErrConfigRequired`、`ErrTransportUnsupported`、
`ErrNoCapNetRaw`、`ErrPingSocketDenied`、`ErrHandshakeTimeout`、`ErrClosed`、
`ErrNoRoute`、`ErrRecordTooLarge`、`ErrNonceCollision`。
