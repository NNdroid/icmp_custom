package tunnel

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Logger
//
// Logging is the operator's only window into a tunnel that carries no
// diagnostics of its own, and the level strings come straight from a config
// file, so both the parsing and the filtering have to be pinned.
// ---------------------------------------------------------------------------

func TestLogLevelParsesTheConfiguredStrings(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"debug", LogLevelDebug},
		{"DEBUG", LogLevelDebug},
		{"  debug  ", LogLevelDebug},
		{"info", LogLevelInfo},
		{"warn", LogLevelWarn},
		{"warning", LogLevelWarn},
		{"error", LogLevelError},
		{"", LogLevelInfo},        // the documented default
		{"verbose", LogLevelInfo}, // unknown falls back to info
		{"trace", LogLevelInfo},
	}
	for _, tc := range cases {
		if got := LogLevel(tc.in); got != tc.want {
			t.Fatalf("LogLevel(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestStdLoggerFiltersByLevel and the levels must stay ordered so a caller can
// compare them directly: debug < info < warn < error.
func TestLogLevelsAreOrdered(t *testing.T) {
	if !(LogLevelDebug < LogLevelInfo && LogLevelInfo < LogLevelWarn && LogLevelWarn < LogLevelError) {
		t.Fatal("log levels must be ordered so callers can compare them with <")
	}
}

// asLogLines captures everything a stdLogger writes. The standard logger is a
// process-global, so the tests that use it must not run in parallel.
func asLogLines(t *testing.T, fn func()) []string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()

	fn()

	out := strings.TrimSpace(buf.String())
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func TestStdLoggerFiltersByLevel(t *testing.T) {
	cases := []struct {
		name  string
		level int
		want  []string // the prefixes that must reach the output, in order
	}{
		{"debug", LogLevelDebug, []string{"DEBUG", "INFO", "WARN", "ERROR"}},
		{"info", LogLevelInfo, []string{"INFO", "WARN", "ERROR"}},
		{"warn", LogLevelWarn, []string{"WARN", "ERROR"}},
		{"error", LogLevelError, []string{"ERROR"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := asLogLines(t, func() {
				l := stdLogger{level: tc.level}
				l.Debugf("d")
				l.Infof("i")
				l.Warnf("w")
				l.Errorf("e")
			})
			if len(lines) != len(tc.want) {
				t.Fatalf("wrote %d lines, want %d: %v", len(lines), len(tc.want), lines)
			}
			for i, prefix := range tc.want {
				// The prefix is padded to DEBUG's width, so match on the name
				// rather than on the exact bracket contents.
				if !strings.Contains(lines[i], prefix) || !strings.HasPrefix(lines[i], "[") {
					t.Fatalf("line %d = %q, want the %s prefix", i, lines[i], prefix)
				}
			}
		})
	}
}

// TestStdLoggerEmitFormats pins the output shape: the prefix is padded so the
// message columns line up in a log file, which is only worth doing if it is
// stable enough to be greppable.
func TestStdLoggerEmitFormats(t *testing.T) {
	lines := asLogLines(t, func() {
		l := stdLogger{level: LogLevelDebug}
		l.Debugf("dbg %d", 1)
		l.Infof("inf %d", 2)
		l.Warnf("wrn %d", 3)
		l.Errorf("err %d", 4)
	})
	// Prefixes are padded to the width of "DEBUG", so the message columns align.
	want := []string{"[DEBUG] dbg 1", "[INFO ] inf 2", "[WARN ] wrn 3", "[ERROR] err 4"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(lines), len(want), lines)
	}
	for i, w := range want {
		if !strings.Contains(lines[i], w) {
			t.Fatalf("line %d = %q, want %q", i, lines[i], w)
		}
	}
	// The four prefixes are padded to the same width, so every message starts
	// at the same column.
	col := -1
	for _, line := range lines {
		got := strings.Index(line, "dbg ")
		if got < 0 {
			got = strings.Index(line, "inf ")
		}
		if got < 0 {
			got = strings.Index(line, "wrn ")
		}
		if got < 0 {
			got = strings.Index(line, "err ")
		}
		if got < 0 {
			t.Fatalf("line %q has no recognisable message", line)
		}
		if col == -1 {
			col = got
		} else if got != col {
			t.Fatalf("message column %d != %d; prefixes are not padded consistently (%q)", got, col, line)
		}
	}
}

func TestStdLoggerSuppressesBelowItsLevel(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	(stdLogger{level: LogLevelError}).Infof("suppressed")
	if buf.Len() != 0 {
		t.Fatalf("an error-level logger wrote at info: %q", buf.String())
	}
	(stdLogger{level: LogLevelError}).Errorf("emitted")
	if !strings.Contains(buf.String(), "emitted") {
		t.Fatalf("an error-level logger must write at error: %q", buf.String())
	}
}

func TestResolveLoggerPrefersTheInjectedLogger(t *testing.T) {
	injected := &captureLogger{}
	if got := resolveLogger(injected, "error"); got != Logger(injected) {
		t.Fatal("an injected logger must win over the configured level")
	}
	var nilLogger Logger
	if got := resolveLogger(nilLogger, "debug"); got == nil {
		t.Fatal("resolveLogger must never return nil, so call sites can log unconditionally")
	}
	if got := resolveLogger(nil, "warn"); got == nil {
		t.Fatal("a nil logger must be replaced, not returned")
	} else if levelOf(got) != LogLevelWarn {
		t.Fatalf("a nil logger must become a level-filtered std logger, got level %d", levelOf(got))
	}
}

func TestLevelOfClassifiesKnownLoggers(t *testing.T) {
	if got := levelOf(stdLogger{level: LogLevelDebug}); got != LogLevelDebug {
		t.Fatalf("levelOf(debug stdLogger) = %d", got)
	}
	if got := levelOf(stdLogger{level: LogLevelError}); got != LogLevelError {
		t.Fatalf("levelOf(error stdLogger) = %d", got)
	}
	// Nop (and a nil logger) count as "never", which is one past error: hot
	// paths compare against the level and skip formatting entirely.
	if got := levelOf(Nop{}); got != LogLevelError+1 {
		t.Fatalf("levelOf(Nop) = %d, want LogLevelError+1", got)
	}
	if got := levelOf(nil); got != LogLevelError+1 {
		t.Fatalf("levelOf(nil) = %d, want LogLevelError+1", got)
	}
	// Anything else (an injected logger) is assumed to want everything.
	if got := levelOf(&captureLogger{}); got != LogLevelDebug {
		t.Fatalf("levelOf(custom) = %d, want debug (assume verbose)", got)
	}
}

func TestNopNeverWrites(t *testing.T) {
	lines := asLogLines(t, func() {
		// Nop is a value type with no state; calling every method must be a
		// no-op that cannot panic even before any logger is configured.
		n := Nop{}
		n.Debugf("a")
		n.Infof("b")
		n.Warnf("c")
		n.Errorf("d")
	})
	if len(lines) != 0 {
		t.Fatalf("Nop wrote %v", lines)
	}
}

// TestCaptureLoggerHelperIsReusableAcrossGoroutines guards the test helper
// itself: every receive loop and session goroutine can log, so a data race in
// the helper would show up as flaky assertions rather than as a real bug.
func TestCaptureLoggerHelperIsReusableAcrossGoroutines(t *testing.T) {
	l := &captureLogger{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Infof("worker %d", i)
		}(i)
	}
	wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) != 8 {
		t.Fatalf("captured %d lines, want 8", len(l.lines))
	}
}
