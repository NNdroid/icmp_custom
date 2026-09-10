package tunnel

import (
	"log"
	"strings"
	"sync/atomic"
)

// Log levels. The numeric order matches the config file's "log_level" strings
// (debug=0 … error=3) so a caller can compare levels directly.
const (
	LogLevelDebug = 0
	LogLevelInfo  = 1
	LogLevelWarn  = 2
	LogLevelError = 3
)

// LogLevel maps a config string to a level. Unknown or empty values become
// LogLevelInfo, which is the documented default.
func LogLevel(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}

// Logger is the diagnostic sink for both Server and Client. An injected Logger
// replaces the standard logger entirely; pass Nop to silence the component.
//
// Implementations must be safe for concurrent use: every receive loop, session
// goroutine and timer can log.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Nop is a Logger that discards everything.
type Nop struct{}

// Debugf implements Logger.
func (Nop) Debugf(string, ...any) {}

// Infof implements Logger.
func (Nop) Infof(string, ...any) {}

// Warnf implements Logger.
func (Nop) Warnf(string, ...any) {}

// Errorf implements Logger.
func (Nop) Errorf(string, ...any) {}

// stdLogger writes through the standard logger, filtered by level. The prefix
// is padded so debug/info/warn/error columns line up in log files.
type stdLogger struct{ level int }

func (l stdLogger) emit(min int, prefix, format string, args ...any) {
	if l.level > min {
		return
	}
	// The prefix is padded to the width of "DEBUG" so the message columns line
	// up in a log file: an operator greps these lines, and a ragged column
	// makes them read as noise.
	log.Printf("[%-5s] "+format, append([]any{prefix}, args...)...)
}

// Debugf implements Logger.
func (l stdLogger) Debugf(format string, args ...any) {
	l.emit(LogLevelDebug, "DEBUG", format, args...)
}

// Infof implements Logger.
func (l stdLogger) Infof(format string, args ...any) { l.emit(LogLevelInfo, "INFO", format, args...) }

// Warnf implements Logger.
func (l stdLogger) Warnf(format string, args ...any) { l.emit(LogLevelWarn, "WARN", format, args...) }

// Errorf implements Logger.
func (l stdLogger) Errorf(format string, args ...any) {
	l.emit(LogLevelError, "ERROR", format, args...)
}

// globalLogLevel is the package-wide default level, used by any Server/Client
// whose config leaves log_level empty. It is a process-wide knob for embedders
// (and the CLI's --log-level flag path can route through it), and it is atomic
// because components are constructed from many goroutines.
var globalLogLevel atomic.Int32

func init() { globalLogLevel.Store(LogLevelInfo) }

// SetGlobalLogLevel sets the process-wide default level applied to every
// component that does not carry its own explicit log_level or injected Logger.
// Example — turn on debug logging everywhere:
//
//	tunnel.SetGlobalLogLevel(tunnel.LogLevelDebug)
//
// Precedence, most specific wins: an injected Logger (ServerConfig.Logger /
// ClientConfig.Logger) beats everything; then the per-component
// log_level config value; then this global default (info).
func SetGlobalLogLevel(level int) { globalLogLevel.Store(int32(level)) }

// GlobalLogLevel reports the process-wide default level set by
// SetGlobalLogLevel (info until changed).
func GlobalLogLevel() int { return int(globalLogLevel.Load()) }

// resolveLogger returns the injected logger when one was supplied, otherwise a
// standard logger filtered by the configured level string. The result is never
// nil, so call sites may log unconditionally.
func resolveLogger(injected Logger, level string) Logger {
	if injected != nil {
		return injected
	}
	if strings.TrimSpace(level) == "" {
		return stdLogger{level: GlobalLogLevel()}
	}
	return stdLogger{level: LogLevel(level)}
}

// levelOf reports the numeric verbosity of a Logger so hot paths can skip
// formatting a debug message entirely. Nop and a nil logger count as "never".
func levelOf(l Logger) int {
	if s, ok := l.(stdLogger); ok {
		return s.level
	}
	switch l.(type) {
	case nil, Nop:
		return LogLevelError + 1
	}
	return LogLevelDebug
}
