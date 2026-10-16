package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publicDomain has a non-reserved last label; addresses on it are concatenated
// (scripts/check-emails.sh forbids such literals in tracked files).
const publicDomain = "ctf.dev"

func envOf(m map[string]string) func(string, string) string {
	return func(k, fallback string) string {
		if v := m[k]; v != "" {
			return v
		}
		return fallback
	}
}

func writeRoster(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "roster.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ADR-0034 D2 / D5: the process refuses to start (configFromEnv errors, main
// exits 1) whenever the identity configuration is unsafe. There is no
// "ROSTER_FILE unset" mode.
func TestConfigFromEnv_FailClosed(t *testing.T) {
	good := writeRoster(t, "seats:\n  - seat: user1\n")
	empty := writeRoster(t, "")
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"ROSTER_FILE unset", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ADMIN_EMAILS": "admin@ctf.local"}, "ROSTER_FILE is not set"},
		{"ROSTER_FILE points nowhere", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ROSTER_FILE": "/nonexistent/roster.yaml"}, "open"},
		{"ROSTER_FILE empty", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ROSTER_FILE": empty}, "empty"},
		// Security LOW-4: there is no default domain. A valid roster and admin
		// list with EXPECTED_EMAIL_DOMAIN unset (or blank) must still refuse.
		{"EXPECTED_EMAIL_DOMAIN unset", map[string]string{"ROSTER_FILE": good, "ADMIN_EMAILS": "admin@ctf.local"}, "EXPECTED_EMAIL_DOMAIN is empty"},
		{"EXPECTED_EMAIL_DOMAIN blank", map[string]string{"ROSTER_FILE": good, "EXPECTED_EMAIL_DOMAIN": "   "}, "EXPECTED_EMAIL_DOMAIN is empty"},
		{"EXPECTED_EMAIL_DOMAIN not reserved", map[string]string{"ROSTER_FILE": good, "EXPECTED_EMAIL_DOMAIN": "ctf.dev"}, "not a reserved name"},
		{"ADMIN_EMAILS not reserved", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ROSTER_FILE": good, "ADMIN_EMAILS": "ops@" + publicDomain}, "not a reserved name"},
		{"ADMIN_EMAILS overlaps a seat", map[string]string{"EXPECTED_EMAIL_DOMAIN": "ctf.local", "ROSTER_FILE": good, "ADMIN_EMAILS": "user1@ctf.local"}, "ADMIN_EMAILS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := configFromEnv(envOf(c.env))
			if err == nil {
				t.Fatalf("configFromEnv accepted it: %+v", cfg)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name the defect (want %q)", err, c.want)
			}
		})
	}
}

func TestConfigFromEnv_Valid(t *testing.T) {
	good := writeRoster(t, "seats:\n  - seat: user1\n  - seat: user2\n    external: p@partner.example\n")
	cfg, err := configFromEnv(envOf(map[string]string{
		"ROSTER_FILE":           good,
		"EXPECTED_EMAIL_DOMAIN": "ctf.local",
		"ADMIN_EMAILS":          "Admin@ctf.local, ops@ctf.local",
		"OAUTH2_PROXY_AUTH_URL": "http://oauth2.invalid/oauth2/auth",
	}))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Roster == nil || cfg.Roster.SeatCount() != 2 || cfg.Roster.ExternalCount() != 1 {
		t.Fatalf("roster not loaded: %+v", cfg.Roster)
	}
	if cfg.ExpectedEmailDomain != "ctf.local" {
		t.Errorf("EXPECTED_EMAIL_DOMAIN = %q", cfg.ExpectedEmailDomain)
	}
	if got := strings.Join(cfg.AdminEmails, ","); got != "admin@ctf.local,ops@ctf.local" {
		t.Errorf("admins = %q", got)
	}
}
