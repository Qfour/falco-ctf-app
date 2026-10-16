package authpolicy

// R3#5 / R4#2 (review-5x T3, ADR-0034 D2): the email normaliser and the
// reserved-domain rule have a second implementation in platform (shell,
// scripts/lib/roster.sh). The cases live in ONE place, testdata/roster-parity/,
// and both suites read the same files; this is the Go side. A row is never
// dropped to make a side pass: the side that disagrees is the bug.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/identity"
)

type parityRow struct {
	line          int
	input, expect string
}

// minParityRows keeps the table from being emptied (or the reader from
// misparsing it into nothing) and still reading as green.
const (
	minCaseRows     = 35
	minReservedRows = 20
)

// readParity reads one table. {G0}/{G1} are replaced in both columns by the
// folded domains from GoogleMailDomains(), so no mailbox on a public domain is
// written in a tracked file (scripts/check-emails.sh).
func readParity(t *testing.T, name string) []parityRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "roster-parity", name))
	if err != nil {
		t.Fatal(err)
	}
	g := GoogleMailDomains()
	sub := strings.NewReplacer("{G0}", g[0], "{G1}", g[1])
	var rows []parityRow
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First tab only: input may be empty, never contains a tab.
		in, ex, ok := strings.Cut(line, "\t")
		if !ok || strings.Contains(ex, "\t") || ex == "" || ex != strings.TrimSpace(ex) {
			t.Fatalf("%s:%d: want exactly `input<TAB>expect` with a non-blank expect, got %q", name, i+1, line)
		}
		rows = append(rows, parityRow{line: i + 1, input: sub.Replace(in), expect: sub.Replace(ex)})
	}
	return rows
}

func TestParity_NormalizeEmail(t *testing.T) {
	rows := readParity(t, "cases.tsv")
	if len(rows) < minCaseRows {
		t.Fatalf("cases.tsv has %d rows, want at least %d: the table was truncated or misread", len(rows), minCaseRows)
	}
	accepted, rejected := 0, 0
	for _, r := range rows {
		got, ok := NormalizeEmail(r.input)
		if r.expect == "REJECT" {
			rejected++
			if ok {
				t.Errorf("cases.tsv:%d: NormalizeEmail(%q) = %q, want REJECT", r.line, r.input, got)
			}
			continue
		}
		accepted++
		if !ok || got != r.expect {
			t.Errorf("cases.tsv:%d: NormalizeEmail(%q) = %q,%v, want %q", r.line, r.input, got, ok, r.expect)
			continue
		}
		// A normal form is a fixed point: normalising it again changes nothing,
		// so a roster row and a login that were already normal still match.
		if again, ok := NormalizeEmail(got); !ok || again != got {
			t.Errorf("cases.tsv:%d: %q is not a fixed point of NormalizeEmail (-> %q,%v)", r.line, got, again, ok)
		}
	}
	if accepted < 10 || rejected < 15 {
		t.Fatalf("cases.tsv: %d accepted / %d rejected rows: both outcomes must be well covered", accepted, rejected)
	}
}

func TestParity_ReservedDomain(t *testing.T) {
	rows := readParity(t, "reserved-domains.tsv")
	if len(rows) < minReservedRows {
		t.Fatalf("reserved-domains.tsv has %d rows, want at least %d: the table was truncated or misread", len(rows), minReservedRows)
	}
	ok, rej := 0, 0
	for _, r := range rows {
		var verdict string
		if d, err := identity.NormalizeDomain(r.input); err != nil {
			verdict = "REJECT"
		} else if err := identity.CheckReservedDomain(d); err != nil {
			verdict = "REJECT"
		} else {
			verdict = "OK"
		}
		switch r.expect {
		case "OK":
			ok++
		case "REJECT":
			rej++
		default:
			t.Fatalf("reserved-domains.tsv:%d: expect must be OK or REJECT, got %q", r.line, r.expect)
		}
		if verdict != r.expect {
			t.Errorf("reserved-domains.tsv:%d: domain %q -> %s, want %s", r.line, r.input, verdict, r.expect)
		}
	}
	if ok < 5 || rej < 10 {
		t.Fatalf("reserved-domains.tsv: %d OK / %d REJECT rows: both outcomes must be well covered", ok, rej)
	}
}

// The reserved set itself is part of the contract the shell side copies; pin
// it here so a change to the Go set cannot pass while the table stays as is.
func TestParity_ReservedLabelsMatchTheTable(t *testing.T) {
	want := map[string]bool{"local": true, "test": true, "invalid": true, "example": true, "localhost": true}
	got := identity.ReservedLabels()
	if len(got) != len(want) {
		t.Fatalf("ReservedLabels() = %v, want exactly %v", got, want)
	}
	for _, l := range got {
		if !want[l] {
			t.Errorf("ReservedLabels() has %q, not in the pinned set", l)
		}
	}
	rows := readParity(t, "reserved-domains.tsv")
	seen := map[string]bool{}
	for _, r := range rows {
		if r.expect == "OK" {
			seen[r.input[strings.LastIndexByte(r.input, '.')+1:]] = true
		}
	}
	for l := range want {
		if !seen[l] {
			t.Errorf("reserved-domains.tsv has no OK row ending in the reserved label %q", l)
		}
	}
}
