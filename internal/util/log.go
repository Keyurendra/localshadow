package util

import (
	"log/slog"
	"os"
)

func NewLogger(level string, format string) *slog.Logger {
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
	opt := &slog.HandlerOptions{Level: slogLvl}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opt))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opt))
}
