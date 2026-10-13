package identity

import (
	"strings"
	"testing"
)

// Addresses with a NON-reserved domain are assembled from these constants, never
// written as a literal: scripts/check-emails.sh (ADR-0034 V17) fails on any
// tracked file carrying a real-looking address.
const (
	publicDomain   = "ctf.dev"
	lookalikeLabel = "evil-local"
)

// ADR-0034 V10 (scoreboard half): the reserved-name startup check, one defect
// per case. auth-policy's own V10 cases (internal/authpolicy/roster_test.go)
// go through the same Validate.
func TestValidate_OneDefectPerCase(t *testing.T) {
	cases := []struct {
		name       string
		domain     string
		admins     []string
		allowEmpty bool
		wantErr    string // substring; "" = must succeed
		wantDomain string
		wantAdmins []string
	}{
		{name: "reserved .local passes", domain: "ctf.local", wantDomain: "ctf.local"},
		{name: "every reserved label passes", domain: "a.test", wantDomain: "a.test"},
		{name: "invalid", domain: "ctf.invalid", wantDomain: "ctf.invalid"},
		{name: "example", domain: "ctf.example", wantDomain: "ctf.example"},
		{name: "localhost", domain: "ctf.localhost", wantDomain: "ctf.localhost"},
		{name: "single label reserved name passes", domain: "local", wantDomain: "local"},
		{name: "case folded and trimmed", domain: "  CTF.Local ", wantDomain: "ctf.local"},
		{name: "public suffix rejected", domain: "ctf.dev", wantErr: "not a reserved name"},
		{name: "last label must match exactly (evil-local)", domain: "ctf.evil-local", wantErr: "not a reserved name"},
		{name: "reserved word only in the middle", domain: "local.ctf.dev", wantErr: "not a reserved name"},
		{name: "trailing dot rejected", domain: "ctf.local.", wantErr: "empty label"},
		{name: "doubled dot rejected", domain: "ctf..local", wantErr: "empty label"},
		{name: "non-ASCII rejected (Kelvin sign in the domain)", domain: "ctf.\u212aocal", wantErr: "non-ASCII"},
		{name: "domain with @ rejected", domain: "a@ctf.local", wantErr: "contains '@'"},
		{name: "empty domain rejected for auth-policy", domain: "", wantErr: "EXPECTED_EMAIL_DOMAIN is empty"},
		{name: "blank domain rejected for auth-policy", domain: "   ", wantErr: "EXPECTED_EMAIL_DOMAIN is empty"},
		{name: "empty domain allowed for the scoreboard", domain: "", allowEmpty: true, wantDomain: ""},
		{name: "empty domain does not excuse a bad admin", domain: "", allowEmpty: true, admins: []string{"a@" + publicDomain}, wantErr: "ADMIN_EMAILS"},
		{name: "admin on a reserved domain passes and is lower-cased", domain: "ctf.local", admins: []string{" Ops@CTF.local ", ""}, wantDomain: "ctf.local", wantAdmins: []string{"ops@ctf.local"}},
		{name: "admin on a public domain rejected", domain: "ctf.local", admins: []string{"ops@" + publicDomain}, wantErr: "not a reserved name"},
		{name: "admin one bad among good rejected", domain: "ctf.local", admins: []string{"ops@ctf.local", "x@" + publicDomain}, wantErr: "ADMIN_EMAILS[1]"},
		{name: "admin last-label lookalike rejected", domain: "ctf.local", admins: []string{"ops@ctf." + lookalikeLabel}, wantErr: "not a reserved name"},
		{name: "admin trailing dot rejected", domain: "ctf.local", admins: []string{"ops@ctf.local."}, wantErr: "empty label"},
		{name: "admin non-ASCII rejected (Kelvin sign in local part)", domain: "ctf.local", admins: []string{"ops\u212a@ctf.local"}, wantErr: "non-ASCII"},
		{name: "admin without @ rejected", domain: "ctf.local", admins: []string{"ops"}, wantErr: "exactly one '@'"},
		{name: "admin with two @ rejected", domain: "ctf.local", admins: []string{"a@b@ctf.local"}, wantErr: "exactly one '@'"},
		{name: "admin with empty local part rejected", domain: "ctf.local", admins: []string{"@ctf.local"}, wantErr: "exactly one '@'"},
		{name: "admin with empty domain rejected", domain: "ctf.local", admins: []string{"ops@"}, wantErr: "exactly one '@'"},
		{name: "admin with inner space rejected", domain: "ctf.local", admins: []string{"o ps@ctf.local"}, wantErr: "non-ASCII"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Validate(c.domain, c.admins, c.allowEmpty)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("Validate(%q, %q) = %+v, nil; want error containing %q", c.domain, c.admins, cfg, c.wantErr)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("Validate error = %v; want it to contain %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q, %q): unexpected error %v", c.domain, c.admins, err)
			}
			if cfg.Domain != c.wantDomain {
				t.Errorf("Domain = %q, want %q", cfg.Domain, c.wantDomain)
			}
			if strings.Join(cfg.Admins, ",") != strings.Join(c.wantAdmins, ",") {
				t.Errorf("Admins = %q, want %q", cfg.Admins, c.wantAdmins)
			}
		})
	}
}

// The reserved set is part of the contract (ADR-0034 D2): pin it so a label is
// never added or removed without this test (and the ADR) noticing.
func TestReservedLabels_Pinned(t *testing.T) {
	got := strings.Join(ReservedLabels(), ",")
	if want := "local,test,invalid,example,localhost"; got != want {
		t.Fatalf("reserved labels = %s, want %s", got, want)
	}
	// ReservedLabels must hand back a copy: mutating it cannot widen the set.
	l := ReservedLabels()
	l[0] = "com"
	if err := CheckReservedDomain("ctf.com"); err == nil {
		t.Fatal("mutating the returned slice widened the reserved set")
	}
}

func TestCanonical(t *testing.T) {
	if got := Canonical("user7", "ctf.local"); got != "user7@ctf.local" {
		t.Fatalf("Canonical = %q", got)
	}
}
