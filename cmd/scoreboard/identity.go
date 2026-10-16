package main

import (
	"fmt"

	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/serverutil"
)

// identityFromEnv resolves the I8 identity inputs (ADR-0034 D5):
//
//   - EXPECTED_EMAIL_DOMAIN is the domain of the canonical `<seat>@<domain>`
//     identity auth-policy stamps on every participant request. It must equal
//     auth-policy's value. Unset/empty is ALLOWED and means no email is ever a
//     participant's own (self checks are false everywhere: fail-closed) —
//     deliberately not defaulted, since a default would be a guess about the
//     deployment (I7).
//   - when set, its last label must be a reserved name (local, test, invalid,
//     example, localhost), and so must the domain of every ADMIN_EMAILS entry;
//     anything else is a startup error (the same check auth-policy applies), so
//     a mis-set domain can never be one an external IdP could hold.
//
// The returned admins are the normalised (trimmed, lower-cased) ADMIN_EMAILS.
func identityFromEnv(env func(key, fallback string) string) (domain string, admins []string, err error) {
	cfg, err := identity.Validate(env("EXPECTED_EMAIL_DOMAIN", ""), serverutil.SplitCSV(env("ADMIN_EMAILS", "")), true)
	if err != nil {
		return "", nil, fmt.Errorf("identity config: %w", err)
	}
	return cfg.Domain, cfg.Admins, nil
}
