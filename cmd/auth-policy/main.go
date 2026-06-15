// Command auth-policy serves the host↔email authorization check used by
// ingress-nginx's auth-url subrequest. See internal/authpolicy for the
// decision tree.
package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/authpolicy"
	"github.com/Qfour/falco-ctf-app/internal/serverutil"
)

func main() {
	cfg := authpolicy.Config{
		OAuth2ProxyURL:      serverutil.Env("OAUTH2_PROXY_AUTH_URL", "http://oauth2-proxy.oauth2-proxy.svc.cluster.local:80/oauth2/auth"),
		ExpectedEmailDomain: serverutil.Env("EXPECTED_EMAIL_DOMAIN", "ctf.local"),
		UpstreamTimeout:     5 * time.Second,
		// ADMIN_EMAILS is a comma-separated allowlist consulted by
		// /check-admin (scoreboard host gate). Empty / unset = nobody is
		// admin = fail-closed.
		AdminEmails: serverutil.SplitCSV(serverutil.Env("ADMIN_EMAILS", "")),
	}
	addr := serverutil.Env("LISTEN_ADDR", ":8000")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	err := serverutil.Serve(addr, authpolicy.NewHandler(cfg, logger), logger, func() {
		logger.Info("listening",
			"addr", addr,
			"oauth2_proxy", cfg.OAuth2ProxyURL,
			"domain", cfg.ExpectedEmailDomain,
		)
	})
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
