# icmp_custom

An encrypted v2 tunnel over ICMP Echo, delivered as a Go library and a CLI.
Application records travel verbatim as ICMP Echo Request/Reply payloads, with
authentication (PSK + forward-secret Noise_NK), reliable delivery (ARQ),
adaptive MTU search, pacing and rate limiting built in.

- **Library API**: see [LIBRARY.md](LIBRARY.md) — injectable transports,
  `ProtectFD` (Android VpnService exemption), `TargetDialer` (DialContext-style
  forwarding), the logging interface with a global level knob, events and
  stats.
- **Protocol & architecture**: the design document (`DESIGN_ICMP.md`) lives in
  the local `docs/` directory and is not distributed with the repository.

## Platforms

| Platform | Carrier | Role | Privilege |
|---|---|---|---|
| Linux | `SOCK_RAW` ICMPv4+v6 (dual-stack) | server + client | CAP_NET_RAW |
| Android | unprivileged ping socket (`SOCK_DGRAM` + `IPPROTO_ICMP`) | client | ping_group_range |
| Windows / macOS / others | explicit refusal (`ErrTransportUnsupported`) | — | — |

## Build

```sh
go build -trimpath -o icmp_custom .        # local build
./scripts/build.sh v0.1.0                  # 12-target cross build + archives + checksums
```

## CLI

```sh
icmp_custom server -config server.json
icmp_custom client -config client.json
icmp_custom gen-config    # generate keys and config templates
icmp_custom gen-icmp-rules
```

## Tests & CI

```sh
go test ./...          # full suite (fake carrier, runs without root)
go test -race ./...
go test -bench . ./tunnel/
```

CI (`.github/workflows/ci.yml`) runs in two tiers:

- **fast — every push to `main` and every pull request**: gofmt/vet → Linux
  test matrix (race + coverage) → the weak-network benchmark, which fails the
  run unless every seeded profile delivers 100% of the payload with a fully
  drained ARQ.
- **full — `v*` tag pushes and manual runs (release gating)**: adds the 3-OS
  test matrix → benchmark smoke → cross builds (including android/arm64 and
  the 32-bit alignment guards) → **the Android emulator job runs the
  ping-socket carrier tests on a real Android kernel** → 32-bit execution and
  fuzz smoke under QEMU.

Pushing a `v*` tag builds and publishes a release automatically
(`release.yml`).

## License

[GPL-3.0](LICENSE)
