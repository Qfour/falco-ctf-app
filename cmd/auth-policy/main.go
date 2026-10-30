// Command auth-policy serves the identity-roster authorization checks used by
// ingress-nginx's auth-url subrequest. See internal/authpolicy for the
// decision tree and ADR-0034 for the identity model.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/authpolicy"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/serverutil"
)

// configFromEnv builds the service config from the environment and refuses
// (returns an error) on anything ADR-0034 D2 forbids: a missing, empty or
// malformed ROSTER_FILE, an unset EXPECTED_EMAIL_DOMAIN, an EXPECTED_EMAIL_DOMAIN
// or ADMIN_EMAILS domain whose
// last label is not a reserved name, or an overlap between ADMIN_EMAILS and the
// roster. There is no "run without a roster" mode.
func configFromEnv(env func(key, fallback string) string) (authpolicy.Config, error) {
	rawAdmins := serverutil.SplitCSV(env("ADMIN_EMAILS", ""))
	// No default: an unset EXPECTED_EMAIL_DOMAIN must reach identity.Validate as
	// empty so auth-policy refuses to start (it cannot resolve a seat without a
	// domain). The chart always passes a value, and docker-compose / `make
	// deploy-local` pass ctf.local explicitly.
	idCfg, err := identity.Validate(env("EXPECTED_EMAIL_DOMAIN", ""), rawAdmins, false)
	if err != nil {
		return authpolicy.Config{}, fmt.Errorf("identity config: %w", err)
	}
	roster, err := authpolicy.LoadRoster(env("ROSTER_FILE", ""), idCfg.Domain, idCfg.Admins)
	if err != nil {
		return authpolicy.Config{}, err
	}
	return authpolicy.Config{
		OAuth2ProxyURL:      env("OAUTH2_PROXY_AUTH_URL", "http://oauth2-proxy.oauth2-proxy.svc.cluster.local:80/oauth2/auth"),
		ExpectedEmailDomain: idCfg.Domain,
		UpstreamTimeout:     5 * time.Second,
		// ADMIN_EMAILS is a comma-separated allowlist consulted by
		// /check-participant's admin override and by /check-admin; on
		// /check-workspace it is used to refuse (ADR-0050). Empty / unset = nobody
		// is admin = fail-closed. Entries must be reserved-domain static
		// accounts (identity.Validate).
		AdminEmails: idCfg.Admins,
		Roster:      roster,
	}, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := configFromEnv(serverutil.Env)
	if err != nil {
		logger.Error("refusing to start", "err", err)
		os.Exit(1)
	}
	addr := serverutil.Env("LISTEN_ADDR", ":8000")

	err = serverutil.Serve(addr, authpolicy.NewHandler(cfg, logger), logger, func() {
		logger.Info("listening",
			"addr", addr,
			"oauth2_proxy", cfg.OAuth2ProxyURL,
			"domain", cfg.ExpectedEmailDomain,
			"roster_seats", cfg.Roster.SeatCount(),
			"roster_external", cfg.Roster.ExternalCount(),
		)
	})
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
