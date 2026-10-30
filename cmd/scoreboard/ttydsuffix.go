package main

import (
	"fmt"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/view"
)

// ttydSuffixFromEnv reads PORTAL_TTYD_SUFFIX and checks it against the closed DNS
// name grammar (ADR-0047 D6, app#532). Unset or empty is allowed and means the
// Terminal pane is "not configured"; any other value outside the grammar is a
// startup error, so a mis-set suffix is never concatenated into the portal's CSP.
// The error carries the length of the value, not the value.
func ttydSuffixFromEnv(env func(key, fallback string) string) (string, error) {
	v := env("PORTAL_TTYD_SUFFIX", "")
	if err := view.ValidateTtydSuffix(v); err != nil {
		return "", fmt.Errorf("PORTAL_TTYD_SUFFIX: %w", err)
	}
	return v, nil
}
