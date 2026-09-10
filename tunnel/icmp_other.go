//go:build !linux && !android

package tunnel

import (
	"fmt"
	"runtime"
)

// newPlatformICMPTransport reports that this platform cannot provide the ICMP
// carrier.
//
// The failure is a configuration-time error with an actionable message rather
// than a mysterious socket failure or a silent no-op: the ICMP profile needs a
// raw socket (`CAP_NET_RAW`), and no platform covered by this file offers one
// through the standard library.
//
// Desktop Windows and macOS users get exactly this error, which is the intended
// outcome — DESIGN_ICMP.md §4.1 requires an explicit refusal, and explicitly
// forbids silently degrading into a "working" tunnel that carries nothing.
func newPlatformICMPTransport(_ *icmpConfig) (platformICMP, error) {
	return nil, fmt.Errorf(
		"%w: no ICMP carrier is available on %s; "+
			"run the tunnel on Linux, or use a carrier this platform supports",
		ErrTransportUnsupported, runtime.GOOS)
}
