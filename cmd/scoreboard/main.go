// Command scoreboard ingests falcosidekick webhooks, attributes events to
// CTF users via the `ctf-<username>` namespace convention, and serves a
// live dashboard. See internal/scoreboard for the HTTP surface and
// internal/store for persistence guarantees.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	challengesDir := env("CHALLENGES_DIR", "/app/challenges")
	dbPath := env("SCOREBOARD_DB", "/var/lib/scoreboard/scoreboard.db")
	addr := env("LISTEN_ADDR", ":8000")

	cat, err := catalog.Load(challengesDir)
	if err != nil {
		logger.Error("catalog load failed", "dir", challengesDir, "err", err)
		os.Exit(1)
	}
	logger.Info("catalog loaded", "dir", challengesDir, "challenges", cat.IDs())

	st, err := store.Open(dbPath)
	if err != nil {
		logger.Error("store open failed", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	logger.Info("store opened", "path", dbPath, "solved_loaded", st.SolvedCount())

	handler := scoreboard.NewHandler(cat, st, logger, scoreboard.WithDBPath(dbPath))

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
