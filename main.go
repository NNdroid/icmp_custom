package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/NNdroid/icmp_custom/tunnel"
)

// Build metadata. The release workflow overrides these through -ldflags
// (-X main.version=... -X main.commit=... -X main.date=...), so a shipped
// binary can always say exactly what it is.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it takes argv and the two streams and
// returns the process exit code, so every subcommand can be exercised without
// spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		fmt.Fprintln(stderr, "\nerror: a command is required")
		return 2
	}
	switch args[0] {
	case "server":
		return runServer(args[1:], stdout, stderr)
	case "client":
		return runClient(args[1:], stdout, stderr)
	case "gen-keys":
		return runGen(args[1:], stdout, stderr, "gen-keys", genKeys)
	case "gen-magic":
		return runGen(args[1:], stdout, stderr, "gen-magic", genMagic)
	case "gen-icmp-rules":
		return runGen(args[1:], stdout, stderr, "gen-icmp-rules", genICMPRules)
	case "gen-config":
		return runGenConfig(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "icmp_custom %s (commit %s, built %s, %s/%s)\n",
			version, commit, date, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `icmp_custom — a v2 tunnel carried over ICMP echo (IPv4 + IPv6)

Usage:
  icmp_custom <command> [flags]

Commands:
  server          Run the server.  Requires: -c <file>
  client          Run the client.  Requires: -c <file>
  gen-keys        Print a fresh Noise_NK static key pair
  gen-magic       Print a fresh record magic (non-zero, non-printable)
  gen-icmp-rules  Print the firewall rules for the ICMP echo path (v4 + v6)
  gen-config      Print a commented starter config. Flags: -role server|client
  version         Print build metadata
  help            Print this message

Notes:
  * There is exactly one configuration source: -c <file>. No environment
    variables, no default paths. Unknown JSON keys are ignored.
  * The raw ICMP carrier needs CAP_NET_RAW. Prefer the capability over root:
        sudo setcap cap_net_raw+ep $(command -v icmp_custom)
`)
}

// configFlag parses the shared "-c <file>" flag. Every role command requires
// it; there is deliberately no discovery fallback.
func configFlag(args []string, w io.Writer, name string) (string, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	path := fs.String("c", "", "path to the configuration file (required)")
	if err := fs.Parse(args); err != nil {
		return "", false
	}
	if *path == "" {
		fmt.Fprintln(w, "error: -c <file> is required")
		return "", false
	}
	return *path, true
}

func runServer(args []string, stdout, stderr io.Writer) int {
	path, ok := configFlag(args, stderr, "server")
	if !ok {
		return 2
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return fail(stderr, err)
	}
	sc, err := cfg.ServerConfig()
	if err != nil {
		return fail(stderr, err)
	}
	srv, err := tunnel.NewServer(sc)
	if err != nil {
		return fail(stderr, err)
	}
	defer srv.Close()

	fmt.Fprintf(stdout, "icmp_custom %s: server starting (config %s)\n", version, path)
	stop := onSignal(func() {
		fmt.Fprintln(stdout, "shutting down...")
		srv.Close()
	})
	defer stop()

	if err := srv.Start(); err != nil {
		return fail(stderr, err)
	}
	st := srv.Stats()
	fmt.Fprintf(stdout, "server stopped: sessions=%d auth_fail=%d decode_fail=%d replay_drop=%d queue_full=%d send_fail=%d addr_change=%d\n",
		st.Sessions, st.AuthFailures, st.DecodeFailures, st.ReplayDrops, st.QueueFullDrops, st.SendFailures, st.AddressChanges)
	return 0
}

func runClient(args []string, stdout, stderr io.Writer) int {
	path, ok := configFlag(args, stderr, "client")
	if !ok {
		return 2
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return fail(stderr, err)
	}
	cc, err := cfg.ClientConfig()
	if err != nil {
		return fail(stderr, err)
	}
	cli, err := tunnel.NewClient(cc)
	if err != nil {
		return fail(stderr, err)
	}
	defer cli.Close()

	fmt.Fprintf(stdout, "icmp_custom %s: client starting (config %s)\n", version, path)
	stop := onSignal(func() {
		fmt.Fprintln(stdout, "shutting down...")
		cli.Close()
	})
	defer stop()

	if err := cli.Start(); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "client stopped: sessions=%d\n", cli.Stats().Sessions)
	return 0
}

// runGen wraps a pure generator subcommand. Generators take no arguments; any
// positional argument is a mistake worth reporting rather than ignoring.
func runGen(args []string, stdout, stderr io.Writer, name string, fn func(io.Writer) error) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: %s takes no positional arguments\n", name)
		return 2
	}
	if err := fn(stdout); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func runGenConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	role := fs.String("role", "server", "which role to emit: server or client")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch *role {
	case "server", "client":
	default:
		fmt.Fprintf(stderr, "error: -role must be \"server\" or \"client\", got %q\n", *role)
		return 2
	}
	if err := WriteTemplate(stdout, *role); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// onSignal runs fn once on the first interrupt/terminate, and returns a
// function that releases the handler. The handler runs on its own goroutine so
// the command's main goroutine can keep blocking in Start().
func onSignal(fn func()) func() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		fn()
	}()
	return stop
}

// fail prints an error and, when it recognises the failure, an actionable
// hint. The three failure paths the design requires to be distinguishable are
// exactly these: an invalid config, a platform without an ICMP carrier, and a
// missing capability on a platform that has one.
//
// The hint is printed in addition to the error, never instead of it: the error
// already names the specifics, the hint names the fix.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %v\n", err)
	switch {
	case errors.Is(err, tunnel.ErrConfigRequired):
		fmt.Fprintln(stderr, "hint: fix the configuration; `gen-config -role server|client` prints a commented template")
	case errors.Is(err, tunnel.ErrTransportUnsupported):
		fmt.Fprintf(stderr, "hint: this build has no ICMP carrier on %s/%s; run the tunnel on Linux, or use the Android ping-socket build\n",
			runtime.GOOS, runtime.GOARCH)
	case errors.Is(err, tunnel.ErrNoCapNetRaw):
		fmt.Fprintln(stderr, "hint: grant the capability instead of using root:  sudo setcap cap_net_raw+ep $(command -v icmp_custom)")
	case errors.Is(err, tunnel.ErrPingSocketDenied):
		fmt.Fprintln(stderr, "hint: widen the ping group range:  sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"")
	}
	return 1
}
