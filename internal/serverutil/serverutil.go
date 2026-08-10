// Package serverutil holds the small HTTP-server bootstrap shared by the
// scoreboard and auth-policy commands: env lookup and a listen + graceful
// shutdown loop. Keeping it here avoids duplicating the lifecycle (and its
// subtle shutdown/timeout details) across both main packages.
package serverutil

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Env returns the value of key, or fallback when key is unset or empty.
func Env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// EnvInt returns the integer value of key, or fallback when key is unset,
// empty, or not a valid base-10 integer. A malformed value falls back rather
// than erroring so a fat-fingered env var degrades to the safe default instead
// of failing startup — the score knobs (#40) are tuning, not correctness.
func EnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return n
}

// SplitCSV parses a comma-separated value: trims whitespace, drops empties.
func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Serve runs h on addr until SIGINT/SIGTERM, then gracefully shuts down with a
// 5s deadline. onListen (if non-nil) is called just before ListenAndServe so
// the caller can log its startup line. Returns the first non-graceful error.
func Serve(addr string, h http.Handler, logger *slog.Logger, onListen func()) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		if onListen != nil {
			onListen()
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
