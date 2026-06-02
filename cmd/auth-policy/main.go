// Command auth-policy serves the host↔email authorization check used by
// ingress-nginx's auth-url subrequest. See internal/authpolicy for the
// decision tree.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/authpolicy"
)

func main() {
	cfg := authpolicy.Config{
		OAuth2ProxyURL:      env("OAUTH2_PROXY_AUTH_URL", "http://oauth2-proxy.oauth2-proxy.svc.cluster.local:80/oauth2/auth"),
		ExpectedEmailDomain: env("EXPECTED_EMAIL_DOMAIN", "ctf.local"),
		UpstreamTimeout:     5 * time.Second,
		// ADMIN_EMAILS is a comma-separated allowlist consulted by
		// /check-admin (scoreboard host gate). Empty / unset = nobody is
		// admin = fail-closed.
		AdminEmails: splitCSV(env("ADMIN_EMAILS", "")),
	}
	addr := env("LISTEN_ADDR", ":8000")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	srv := &http.Server{
		Addr:              addr,
		Handler:           authpolicy.NewHandler(cfg, logger),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening",
			"addr", addr,
			"oauth2_proxy", cfg.OAuth2ProxyURL,
			"domain", cfg.ExpectedEmailDomain,
		)
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

// splitCSV parses a comma-separated env var. Whitespace around items is
// trimmed; empty items are dropped.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
