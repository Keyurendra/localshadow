package util

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

func NewLogger(level, format string, withSource bool) *slog.Logger {
	var slogLvl slog.Level
	switch level {
	case "debug":
		slogLvl = slog.LevelDebug
	case "warn":
		slogLvl = slog.LevelWarn
	case "error":
		slogLvl = slog.LevelError
	default:
		slogLvl = slog.LevelInfo
	}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level:     slogLvl,
			AddSource: withSource,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key != slog.TimeKey {
					return a
				}
				a.Value = slog.TimeValue(a.Value.Time().UTC())
				return a
			},
		}))
	}
	return slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:     slogLvl,
		AddSource: withSource,
		NoColor:   format != "pretty",
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key != slog.TimeKey {
				return a
			}
			a.Value = slog.TimeValue(a.Value.Time().UTC())
			return a
		},
		TimeFormat: time.DateTime,
	}))
}
