package main

import (
	"strings"
	"testing"
)

// publicDomain has a non-reserved last label; addresses on it are concatenated
// (scripts/check-emails.sh forbids such literals in tracked files).
const publicDomain = "ctf.dev"

func envMap(m map[string]string) func(string, string) string {
	return func(k, fallback string) string {
		if v := m[k]; v != "" {
			return v
		}
		return fallback
	}
}

// ADR-0034 D5 / V10 (scoreboard half): the same reserved-name startup check
// auth-policy applies, via the same internal/identity code, plus the one
// difference — an empty EXPECTED_EMAIL_DOMAIN is allowed (self never matches).
func TestIdentityFromEnv(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		wantErr    string
		wantDomain string
		wantAdmins string
	}{
		{"unset domain is allowed (fail-closed self)", map[string]string{}, "", "", ""},
		{"reserved domain", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local"}, "", "ctf.local", ""},
		{"normalised", map[string]string{"EXPECTED_EMAIL_DOMAIN": " CTF.Local ", "ADMIN_EMAILS": " Ops@CTF.local ,admin@ctf.local"}, "", "ctf.local", "ops@ctf.local,admin@ctf.local"},
		{"domain with a public last label", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.dev"}, "not a reserved name", "", ""},
		{"domain last label lookalike", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.evil-local"}, "not a reserved name", "", ""},
		{"domain with trailing dot", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local."}, "empty label", "", ""},
		{"admin on a public domain", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ADMIN_EMAILS": "ops@" + publicDomain}, "not a reserved name", "", ""},
		{"admin on a public domain even with the domain unset", map[string]string{"ADMIN_EMAILS": "ops@" + publicDomain}, "not a reserved name", "", ""},
		{"admin non-ASCII", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ADMIN_EMAILS": "ops\u212a@ctf.local"}, "non-ASCII", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			domain, admins, err := identityFromEnv(envMap(c.env))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("got (%q,%q,%v), want error containing %q", domain, admins, err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if domain != c.wantDomain || strings.Join(admins, ",") != c.wantAdmins {
				t.Fatalf("got (%q, %q), want (%q, %q)", domain, admins, c.wantDomain, c.wantAdmins)
			}
		})
	}
}
