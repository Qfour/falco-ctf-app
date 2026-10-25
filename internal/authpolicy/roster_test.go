package authpolicy

// ADR-0034 V10: the startup validation of the roster, one defect per case. The
// control row proves the base document is valid, so every failing row fails
// for its own single defect and not for something else in the fixture.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// foldTest is a synthetic folded-domain set: the gmail rule is exercised on a
// reserved domain so no real address is ever written down (ADR-0034 D11).
var foldTest = []string{"fold.example", "alias.example"}

// publicDomain is a domain whose last label is NOT reserved; addresses on it are
// assembled by concatenation so the source carries no such literal.
const publicDomain = "ctf.dev"

const baseRoster = `
seats:
  - seat: user1
  - seat: user2
    external: person.two@partner.example
  - seat: user3
`

func TestParseRoster_Control(t *testing.T) {
	r, err := parseRoster([]byte(baseRoster), "ctf.local", []string{"admin@ctf.local"}, foldTest)
	if err != nil {
		t.Fatalf("control roster rejected: %v", err)
	}
	if r.SeatCount() != 3 || r.ExternalCount() != 1 || r.Domain() != "ctf.local" {
		t.Fatalf("control roster: seats=%d external=%d domain=%q", r.SeatCount(), r.ExternalCount(), r.Domain())
	}
}

func TestParseRoster_OneDefectPerCase(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		domain  string   // "" -> ctf.local
		admins  []string // nil -> admin@ctf.local
		wantErr string
	}{
		// --- file shape
		{name: "empty file", doc: "", wantErr: "empty"},
		{name: "comment-only file", doc: "# nothing here\n", wantErr: "empty"},
		{name: "seats: [] (zero seats)", doc: "seats: []\n", wantErr: "no seats"},
		{name: "seats key absent (null)", doc: "seats:\n", wantErr: "no seats"},
		{name: "unknown top-level key", doc: "seats:\n  - seat: user1\nextra: 1\n", wantErr: "structure error (unknown key or wrong type) at line 3"},
		{name: "typo'd top-level key (seat: instead of seats:)", doc: "seat:\n  - seat: user1\n", wantErr: "structure error (unknown key or wrong type) at line 1"},
		{name: "unknown row key", doc: "seats:\n  - seat: user1\n    emial: a@b.example\n", wantErr: "structure error (unknown key or wrong type) at line 3"},
		{name: "external as a list (at most one)", doc: "seats:\n  - seat: user1\n    external: [a@p.example, b@p.example]\n", wantErr: "structure error (unknown key or wrong type) at line 3"},
		{name: "two YAML documents", doc: "seats:\n  - seat: user1\n---\nseats:\n  - seat: user2\n", wantErr: "more than one"},
		{name: "not YAML at all", doc: "seats: [\n", wantErr: "roster: parse: syntax error"},

		// --- seats
		{name: "duplicate seat", doc: "seats:\n  - seat: user1\n  - seat: user1\n", wantErr: "seats[1]: duplicate seat (same as seats[0])"},
		{name: "seat with upper case", doc: "seats:\n  - seat: User1\n", wantErr: "must match"},
		{name: "seat with leading hyphen", doc: "seats:\n  - seat: -user1\n", wantErr: "must match"},
		{name: "seat with a space", doc: "seats:\n  - seat: \"user 1\"\n", wantErr: "non-ASCII"},
		{name: "seat longer than 63", doc: "seats:\n  - seat: " + strings.Repeat("a", 64) + "\n", wantErr: "must match"},
		{name: "seat with a trailing hyphen (valid before app#480)", doc: "seats:\n  - seat: user1-\n", wantErr: "must match"},
		{name: "seat of 54 characters (one over the 53 limit)", doc: "seats:\n  - seat: a" + strings.Repeat("b", 53) + "\n", wantErr: "must match"},
		{name: "empty seat", doc: "seats:\n  - seat: \"\"\n", wantErr: "must match"},
		{name: "seat missing", doc: "seats:\n  - external: a@p.example\n", wantErr: "must match"},
		{name: "non-ASCII seat (Kelvin sign)", doc: "seats:\n  - seat: \"mar\u212a\"\n", wantErr: "non-ASCII"},

		// --- externals
		{name: "duplicate external (exact)", doc: "seats:\n  - seat: user1\n    external: a@p.example\n  - seat: user2\n    external: a@p.example\n", wantErr: "duplicates"},
		{name: "duplicate external (case differs)", doc: "seats:\n  - seat: user1\n    external: A@P.example\n  - seat: user2\n    external: a@p.EXAMPLE\n", wantErr: "duplicates"},
		{name: "duplicate external (dots differ, folded domain)", doc: "seats:\n  - seat: user1\n    external: a.b@fold.example\n  - seat: user2\n    external: ab@fold.example\n", wantErr: "duplicates"},
		{name: "duplicate external (+tag differs, folded domain)", doc: "seats:\n  - seat: user1\n    external: ab@fold.example\n  - seat: user2\n    external: ab+x@fold.example\n", wantErr: "duplicates"},
		{name: "duplicate external (other folded domain unifies)", doc: "seats:\n  - seat: user1\n    external: ab@fold.example\n  - seat: user2\n    external: a.b@alias.example\n", wantErr: "duplicates"},
		{name: "external local part empty after normalisation", doc: "seats:\n  - seat: user1\n    external: \"+x@fold.example\"\n", wantErr: "not a usable email"},
		{name: "external local part only dots after normalisation", doc: "seats:\n  - seat: user1\n    external: \"..@fold.example\"\n", wantErr: "not a usable email"},
		{name: "external blank", doc: "seats:\n  - seat: user1\n    external: \"\"\n", wantErr: "blank"},
		{name: "external without @", doc: "seats:\n  - seat: user1\n    external: nobody\n", wantErr: "not a usable email"},
		{name: "external with two @", doc: "seats:\n  - seat: user1\n    external: a@b@p.example\n", wantErr: "not a usable email"},
		{name: "external with empty domain label", doc: "seats:\n  - seat: user1\n    external: a@p..example\n", wantErr: "not a usable email"},
		{name: "external with trailing dot domain", doc: "seats:\n  - seat: user1\n    external: a@p.example.\n", wantErr: "not a usable email"},
		{name: "external non-ASCII (Kelvin sign)", doc: "seats:\n  - seat: user1\n    external: \"mar\u212a@p.example\"\n", wantErr: "non-ASCII"},
		{name: "external non-ASCII domain", doc: "seats:\n  - seat: user1\n    external: \"a@p\u00e9.example\"\n", wantErr: "non-ASCII"},
		{name: "external in EXPECTED_EMAIL_DOMAIN", doc: "seats:\n  - seat: user1\n    external: x@ctf.local\n", wantErr: "EXPECTED_EMAIL_DOMAIN"},
		{name: "external in EXPECTED_EMAIL_DOMAIN (upper case)", doc: "seats:\n  - seat: user1\n    external: x@CTF.LOCAL\n", wantErr: "EXPECTED_EMAIL_DOMAIN"},

		// --- overlap with ADMIN_EMAILS (compared after normalisation)
		{name: "external is an admin", doc: "seats:\n  - seat: user1\n    external: ops@partner.example\n", admins: []string{"ops@partner.example"}, wantErr: "ADMIN_EMAILS"},
		{name: "external is an admin (case differs)", doc: "seats:\n  - seat: user1\n    external: OPS@Partner.Example\n", admins: []string{"ops@partner.example"}, wantErr: "ADMIN_EMAILS"},
		{name: "seat canonical email is an admin", doc: "seats:\n  - seat: ops\n", admins: []string{"ops@ctf.local"}, wantErr: "ADMIN_EMAILS"},
		{name: "seat canonical email is an admin (case differs)", doc: "seats:\n  - seat: ops\n", admins: []string{"OPS@CTF.LOCAL"}, wantErr: "ADMIN_EMAILS"},

		// --- EXPECTED_EMAIL_DOMAIN / ADMIN_EMAILS reserved-name check
		{name: "domain not reserved", doc: baseRoster, domain: "ctf.dev", wantErr: "not a reserved name"},
		{name: "domain last label only looks reserved (evil-local)", doc: baseRoster, domain: "ctf.evil-local", wantErr: "not a reserved name"},
		{name: "domain with trailing dot", doc: baseRoster, domain: "ctf.local.", wantErr: "empty label"},
		{name: "domain empty", doc: baseRoster, domain: " ", wantErr: "EXPECTED_EMAIL_DOMAIN is empty"},
		{name: "domain non-ASCII", doc: baseRoster, domain: "ctf.\u212aocal", wantErr: "non-ASCII"},
		{name: "admin on a non-reserved domain", doc: baseRoster, admins: []string{"ops@" + publicDomain}, wantErr: "not a reserved name"},
		{name: "admin non-ASCII", doc: baseRoster, admins: []string{"op\u212a@ctf.local"}, wantErr: "non-ASCII"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			domain, admins := c.domain, c.admins
			if domain == "" {
				domain = "ctf.local"
			}
			if admins == nil {
				admins = []string{"admin@ctf.local"}
			}
			r, err := parseRoster([]byte(c.doc), domain, admins, foldTest)
			if err == nil {
				t.Fatalf("accepted a roster with this defect (seats=%d external=%d)", r.SeatCount(), r.ExternalCount())
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not name the defect (want substring %q)", err, c.wantErr)
			}
		})
	}
}

// ADR-0034 D3 / security LOW-2: a startup error names a row by index or line,
// never by a value. The file is personal data once an `external` is present, and
// a CrashLoop would print the message on every restart. Each document below
// carries a marker in the position that the old messages echoed (seat, external,
// an unknown key's name, a scalar of the wrong type, a duplicate); the error
// must still be raised and must contain none of them.
func TestParseRoster_ErrorsNeverEchoValues(t *testing.T) {
	const m = "leakmarker"
	cases := []struct {
		name   string
		doc    string
		admins []string
	}{
		{"seat holding an email (shape)", "seats:\n  - seat: " + m + ".seat@partner.example\n", nil},
		{"seat with upper case", "seats:\n  - seat: " + strings.ToUpper(m) + "\n", nil},
		{"seat non-ASCII", "seats:\n  - seat: \"" + m + "\u212a\"\n", nil},
		{"duplicate seat", "seats:\n  - seat: " + m + "\n  - seat: " + m + "\n", nil},
		{"seat is an admin", "seats:\n  - seat: " + m + "\n", []string{m + "@ctf.local"}},
		{"external blank-ish shape", "seats:\n  - seat: user1\n    external: " + m + "\n", nil},
		{"external two @", "seats:\n  - seat: user1\n    external: " + m + "@a@partner.example\n", nil},
		{"external non-ASCII", "seats:\n  - seat: user1\n    external: \"" + m + "\u212a@partner.example\"\n", nil},
		{"external in the seat domain", "seats:\n  - seat: user1\n    external: " + m + "@ctf.local\n", nil},
		{"external is an admin", "seats:\n  - seat: user1\n    external: " + m + "@partner.example\n", []string{m + "@partner.example"}},
		{"duplicate external", "seats:\n  - seat: user1\n    external: " + m + "@partner.example\n  - seat: user2\n    external: " + m + "@partner.example\n", nil},
		{"unknown row key named like an email", "seats:\n  - seat: user1\n    " + m + ": x\n", nil},
		{"unknown top-level key", "seats:\n  - seat: user1\n" + m + ": 1\n", nil},
		{"seat of the wrong YAML type", "seats:\n  - seat: [" + m + "@partner.example]\n", nil},
		{"external of the wrong YAML type", "seats:\n  - seat: user1\n    external: {" + m + ": " + m + "}\n", nil},
		{"seats is a scalar", "seats: " + m + "@partner.example\n", nil},
		{"syntax error carrying a value", "seats: [" + m + "@partner.example\n", nil},
		{"syntax error, unbalanced quote", "seats:\n  - seat: \"" + m + "@partner.example\n", nil},
		{"second document", "seats:\n  - seat: user1\n---\nseats:\n  - seat: " + m + "\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			admins := c.admins
			if admins == nil {
				admins = []string{"admin@ctf.local"}
			}
			_, err := parseRoster([]byte(c.doc), "ctf.local", admins, foldTest)
			if err == nil {
				t.Fatal("document with this defect was accepted: the case does not test the error text")
			}
			if strings.Contains(strings.ToLower(err.Error()), m) {
				t.Fatalf("startup error echoes a value from the roster: %q", err)
			}
		})
	}
}

// The same rule for the other startup input that can hold a mailbox: a mistyped
// ADMIN_EMAILS element is named by position.
func TestParseRoster_AdminErrorsNeverEchoValues(t *testing.T) {
	// The domain half of an entry is a value too (R3#11): a mistyped entry's
	// domain, rejected as not reserved or as not a plausible domain, is not echoed.
	for _, adm := range []string{"leakmarker@" + publicDomain, "leakmarker\u212a@ctf.local", "leakmarker", "leak@marker@ctf.local",
		"ops@leakmarker." + "notreserved", "ops@leakmarker.local.", "ops@leakmarker..local", "ops@ctf." + "leakmarker"} {
		_, err := parseRoster([]byte(baseRoster), "ctf.local", []string{"admin@ctf.local", adm}, foldTest)
		if err == nil {
			t.Fatalf("admin %q accepted", adm)
		}
		if strings.Contains(err.Error(), "leakmarker") || !strings.Contains(err.Error(), "ADMIN_EMAILS[1]") {
			t.Fatalf("admin error %q must name the entry by position (ADMIN_EMAILS[1]) and not echo it", err)
		}
	}
}

// Reserved domains are checked by their LAST label: every reserved name is
// accepted as a roster domain, so the rejection cases above are about the
// label and not about the check being too strict.
func TestParseRoster_EveryReservedLabelAccepted(t *testing.T) {
	for _, d := range []string{"ctf.local", "ctf.test", "ctf.invalid", "ctf.example", "ctf.localhost", "example"} {
		if _, err := parseRoster([]byte(baseRoster), d, nil, foldTest); err != nil {
			t.Errorf("domain %q rejected: %v", d, err)
		}
	}
}

// LoadRoster is the file entry point: missing, unset, oversize and unreadable
// are all startup errors (there is no "no roster" mode).
func TestLoadRoster_FileErrors(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(good, []byte(baseRoster), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte("seats:\n"+strings.Repeat("  # padding\n", maxRosterBytes/12+2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoster(good, "ctf.local", nil); err != nil {
		t.Fatalf("good file: %v", err)
	}
	for name, path := range map[string]string{
		"path unset":     "",
		"path blank":     "  ",
		"file missing":   filepath.Join(dir, "absent.yaml"),
		"path is a dir":  dir,
		"file empty":     empty,
		"file too large": big,
	} {
		if _, err := LoadRoster(path, "ctf.local", nil); err == nil {
			t.Errorf("%s: LoadRoster accepted %q", name, path)
		}
	}
}

// V10: the normalisation, on its own. Production folds exactly gmail.com and
// googlemail.com; the set is pinned.
func TestGoogleMailDomains_Pinned(t *testing.T) {
	if got := strings.Join(GoogleMailDomains(), ","); got != "gmail.com,googlemail.com" {
		t.Fatalf("folded domains = %q, want gmail.com,googlemail.com (changing this changes who may enter: ADR-0034 D11)", got)
	}
	l := GoogleMailDomains()
	l[0] = "evil.example"
	if GoogleMailDomains()[0] != "gmail.com" {
		t.Fatal("GoogleMailDomains() returned the backing array")
	}
}

func TestNormalizeEmail(t *testing.T) {
	// Production set: the folded domains come from GoogleMailDomains() and the
	// addresses are assembled from them, so no mailbox-shaped literal on a
	// public domain is ever written down (scripts/check-emails.sh, ADR-0034 V17).
	g0, g1 := GoogleMailDomains()[0], GoogleMailDomains()[1]
	cases := []struct {
		in   string
		want string // "" = rejected
	}{
		{"User7@CTF.Local", "user7@ctf.local"},
		{"  a@b.example  ", "a@b.example"},
		{"a.b+c@b.example", "a.b+c@b.example"}, // not a folded domain: kept
		{"a.b+c@" + g0, "ab@" + g0},
		{"A.B@" + strings.ToUpper(g1), "ab@" + g0},
		{"+x@" + g0, ""},
		{".@" + g0, ""},
		{"a@@" + g0, ""},
		{"a@b@" + g0, ""},
		{"@" + g0, ""},
		{"a@", ""},
		{"a", ""},
		{"", ""},
		{"a b@c.example", ""},
		{"a\n@c.example", ""},
		{"a@c.example\n", "a@c.example"}, // trailing whitespace is trimmed, not an identity change
		{"mar\u212a@ctf.local", ""},
		{"a@c.example.", ""},
		{"a@.example", ""},
	}
	for _, c := range cases {
		got, ok := NormalizeEmail(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("NormalizeEmail(%q) = %q, want rejection", c.in, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q,%v, want %q", c.in, got, ok, c.want)
		}
	}
}

// The same function is applied to the table and to the request, so a roster
// row and a login that differ only by folding resolve to the same seat.
func TestResolve_RowAndRequestNormalisedAlike(t *testing.T) {
	r, err := parseRoster([]byte("seats:\n  - seat: user1\n    external: A.B+row@fold.example\n  - seat: user2\n"), "ctf.local", nil, foldTest)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ab@fold.example", "A.B@alias.example", "a.b+whatever@FOLD.example", " ab@fold.example "} {
		if seat, ok := r.Resolve(id); !ok || seat != "user1" {
			t.Errorf("Resolve(%q) = %q,%v, want user1", id, seat, ok)
		}
	}
	for _, id := range []string{"", "ab", "abc@fold.example", "user1@fold.example", "user1@other.example", "user3@ctf.local", "+x@fold.example", "user1+x@ctf.local", "USER1@ctf.local.", "user2@ctf.local@x"} {
		if seat, ok := r.Resolve(id); ok {
			t.Errorf("Resolve(%q) = %q, want unresolved", id, seat)
		}
	}
	var nilRoster *Roster
	if _, ok := nilRoster.Resolve("user1@ctf.local"); ok {
		t.Error("nil roster resolved an identity")
	}
}
