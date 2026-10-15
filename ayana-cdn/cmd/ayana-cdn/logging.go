package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
)

// logLevel is shared by every logger so SIGHUP can change verbosity live.
var logLevel = new(slog.LevelVar)

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown level %q (use debug, info, warn or error)", s)
}

// newLogger builds the process logger. Under systemd (JOURNAL_STREAM set) the
// timestamp is dropped because journald records its own.
func newLogger(w io.Writer, format string) *slog.Logger {
	underJournal := os.Getenv("JOURNAL_STREAM") != ""
	opts := &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if underJournal && len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// httpErrorLog adapts net/http's *log.Logger output to slog with sensible
// levels: ACME problems are warnings (they explain certificate failures),
// TLS handshake noise from scanners is debug.
func httpErrorLog(l *slog.Logger, component string) *log.Logger {
	return log.New(errorLogWriter{l: l, component: component}, "", 0)
}

type errorLogWriter struct {
	l         *slog.Logger
	component string
}

func (w errorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	level := slog.LevelInfo
	switch {
	case strings.Contains(msg, "acme/autocert") || strings.Contains(msg, "acme:"):
		level = slog.LevelWarn
	case strings.Contains(msg, "panic"):
		level = slog.LevelError
	case strings.Contains(msg, "TLS handshake error"),
		strings.Contains(msg, "use of closed network connection"),
		strings.Contains(msg, "connection reset by peer"):
		level = slog.LevelDebug
	}
	w.l.Log(context.Background(), level, msg, "component", w.component)
	return len(p), nil
}
