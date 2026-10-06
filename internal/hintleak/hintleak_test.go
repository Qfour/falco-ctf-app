package hintleak_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

func one(src, text string) []hintleak.Item { return []hintleak.Item{{Source: src, Text: text}} }

// TestHintLeakChecker_Mutation is ADR-0026 V6: the checker must be able to
// fail. Synthetic inputs pin each clause of the D5 rule; the replica cases
// mutate an in-memory copy of the REAL catalog.
func TestHintLeakChecker_Mutation(t *testing.T) {
	t.Run("synthetic", func(t *testing.T) {
		const hintOfB = "tarで固めてから外へ送り出す手順を考える"
		tests := []struct {
			name    string
			in      hintleak.Input
			wantRed bool
		}{
			{
				name: "a hint sentence of another mission mixed into a fixture is RED",
				in: hintleak.Input{
					Hints:   one("B hints[2]", hintOfB),
					Free:    one("A briefing", "全く関係のない導入文だけがここにある"),
					Targets: one("A/fixtures/welcome.txt", "ようこそ。"+hintOfB+"。以上。"),
				},
				wantRed: true,
			},
			{
				name: "a sentence that is also free-display text is GREEN",
				in: hintleak.Input{
					Hints:   one("B hints[2]", hintOfB),
					Free:    one("B briefing", "導入: "+hintOfB),
					Targets: one("A/fixtures/welcome.txt", hintOfB),
				},
				wantRed: false,
			},
			{
				// The 10-rune run "abcdefghij" exists only across the boundary of
				// two free items. Cut per item it is NOT free; if items were
				// joined it would be (the loose side this rule closes).
				name: "a run that straddles two free items is NOT counted as free (RED)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "abcdefghijklm"),
					Free:    []hintleak.Item{{Source: "x", Text: "xxabcde"}, {Source: "y", Text: "fghijklm"}},
					Targets: one("A/fixtures/f", "..abcdefghijklm.."),
				},
				wantRed: true,
			},
			{
				name: "whitespace is removed before matching (RED)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "ab cd ef gh ij kl"),
					Targets: one("A/fixtures/f", "abcdefghijkl"),
				},
				wantRed: true,
			},
			{
				name: "case is not folded (GREEN)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "abcdefghijklm"),
					Targets: one("A/fixtures/f", "ABCDEFGHIJKLM"),
				},
				wantRed: false,
			},
			{
				// Pins n = 10 exactly: the shared run is 10 runes inside longer
				// texts (a 11/12-rune n would find nothing; a 9-rune n is covered below).
				name: "a shared run of exactly 10 runes is RED",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "xxabcdefghijyy"),
					Targets: one("A/fixtures/f", "..abcdefghij.."),
				},
				wantRed: true,
			},
			{
				// Window loop boundary: the only window of a 10-rune item is its last.
				name: "a hint item of exactly 10 runes (whitespace excluded) is RED",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "abcde fghij"),
					Targets: one("A/fixtures/f", "abcdefghij"),
				},
				wantRed: true,
			},
			{
				name: "ideographic space U+3000 and NBSP U+00A0 are removed (RED)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "abcde\u3000fghij\u00a0klm"),
					Targets: one("A/fixtures/f", "abcdefghijklm"),
				},
				wantRed: true,
			},
			{
				// Only unicode.IsSpace runes are removed: U+200B (a format character, not
				// White_Space) stays, so it breaks the run. This is the documented limit
				// of D5 (reviewed by hand, dev-flow V8), pinned so it cannot drift silently.
				name: "U+200B is NOT removed (GREEN)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "abcde\u200bfghijklm"),
					Targets: one("A/fixtures/f", "abcdefghijklm"),
				},
				wantRed: false,
			},
			{
				name: "no NFKC: full-width letters differ from ASCII (GREEN)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "\uff41\uff42\uff43\uff44\uff45\uff46\uff47\uff48\uff49\uff4a\uff4b"),
					Targets: one("A/fixtures/f", "abcdefghijk"),
				},
				wantRed: false,
			},
			{
				name: "9 shared runes are below the n-gram length (GREEN)",
				in: hintleak.Input{
					Hints:   one("B hints[1]", "abcdefghi"),
					Targets: one("A/fixtures/f", "..abcdefghi.."),
				},
				wantRed: false,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				vs, err := hintleak.Check(tt.in)
				if err != nil {
					t.Fatalf("Check: %v", err)
				}
				if got := len(vs) > 0; got != tt.wantRed {
					t.Fatalf("red=%v, want %v; violations=%d\n%s", got, tt.wantRed, len(vs), describe(vs))
				}
			})
		}
	})

	t.Run("empty or malformed input is an error, never a clean result", func(t *testing.T) {
		valid := hintleak.Input{Hints: one("h", "abcdefghijk"), Targets: one("f", "abcdefghijk")}
		noHints := valid
		noHints.Hints = nil
		noFixtures := valid
		noFixtures.Targets = nil
		for name, in := range map[string]hintleak.Input{"zero input": {}, "no hint item": noHints, "no target item": noFixtures} {
			if _, err := hintleak.Check(in); !errors.Is(err, hintleak.ErrEmptyInput) {
				t.Errorf("%s: err = %v, want ErrEmptyInput", name, err)
			}
		}
		// every item group is validated, not only the fixtures
		badFixture, badFree, badHint := valid, valid, valid
		badFixture.Targets = one("A/fixtures/binary", "abc\xff\xfedefghijk")
		badFree.Free = one("A/rule.yaml", "abc\xff\xfedefghijk")
		badHint.Hints = one("B hints[1]", "abc\xff\xfedefghijk")
		for want, in := range map[string]hintleak.Input{"A/fixtures/binary": badFixture, "A/rule.yaml": badFree, "B hints[1]": badHint} {
			if _, err := hintleak.Check(in); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("non-UTF-8 item %q: err = %v, want an error naming the item", want, err)
			}
		}
		// boundary: items shorter than n are valid input and simply yield no n-gram
		short := hintleak.Input{Hints: one("h", "abcdefghi"), Targets: one("f", "abcdefghi")}
		if vs, err := hintleak.Check(short); err != nil || len(vs) != 0 {
			t.Errorf("9-rune items: violations=%d err=%v, want a clean result", len(vs), err)
		}
	})

	// --- replicas of the real catalog -------------------------------------
	real := loadContent(t)

	checkScope := func(t *testing.T, c content, name string) []hintleak.Violation {
		t.Helper()
		for _, s := range c.scopes() {
			if s.name != name {
				continue
			}
			in, err := c.input(s)
			if err != nil {
				t.Fatal(err)
			}
			vs, err := hintleak.Check(in)
			if err != nil {
				t.Fatal(err)
			}
			return vs
		}
		t.Fatalf("scope %q not found", name)
		return nil
	}

	t.Run("replica: unmutated copy is green in every scope (control)", func(t *testing.T) {
		c := real.clone()
		for _, s := range c.scopes() {
			if vs := checkScope(t, c, s.name); len(vs) > 0 {
				t.Fatalf("scope %s is not clean before any mutation:\n%s", s.name, describe(vs))
			}
		}
	})

	t.Run("replica: 02's expected answer (14 runes) mixed into a fixture is RED", func(t *testing.T) {
		const id = "02-credential-files"
		j, ok := real.journeys[id]
		if !ok || len(j.Hints) == 0 {
			t.Fatalf("%s has no journey hints in the real catalog", id)
		}
		// Precondition: the answer really is in the hints (so the mutation is a leak).
		if last := j.Hints[len(j.Hints)-1].Text; !strings.Contains(last, "cat /etc/shadow") {
			t.Fatalf("precondition: %s's last hint does not carry the expected answer: %q", id, last)
		}
		c := real.clone()
		c.fixtures = append(c.fixtures, hintleak.Item{
			Source: "01-initial-recon/fixtures/MUTATION.txt",
			Text:   "手順メモ\n  cat /etc/shadow\n",
		})
		vs := checkScope(t, c, "full")
		if len(vs) == 0 {
			t.Fatal("the answer 'cat /etc/shadow' (14 runes without spaces) in a fixture was NOT detected in the full scope")
		}
		for _, v := range vs {
			if v.Target != "01-initial-recon/fixtures/MUTATION.txt" {
				t.Errorf("violation in an unmutated fixture: %s %q", v.Target, v.Gram)
			}
		}
		t.Logf("detected: %d violation(s), e.g. %q from %v", len(vs), vs[0].Gram, vs[0].HintSources)
	})

	t.Run("replica: a sentence free in the full catalog but not in one scenario is RED only there", func(t *testing.T) {
		const (
			marker    = "scope-marker-7f3a-sentence-alpha-beta"
			hintHost  = "01-initial-recon" // in tutorial-intro and in the nimbusbreach scenarios
			freeHost  = "04-key-search"    // free-display host: not in tutorial-intro, no narrative override
			fixtureID = "13-archive-loot/fixtures/MUTATION.txt"
		)
		c := real.clone()
		h := c.journeys[hintHost]
		h.Hints = append(h.Hints, catalog.JourneyHint{Kind: "solution", Text: "追加ヒント: " + marker})
		c.journeys[hintHost] = h
		f := c.journeys[freeHost]
		f.Briefing += "\n" + marker
		c.journeys[freeHost] = f
		c.fixtures = append(c.fixtures, hintleak.Item{Source: fixtureID, Text: marker})

		if _, ok := real.scenarios["tutorial-intro"]; !ok {
			t.Fatal("scenario tutorial-intro not found")
		}
		red := map[string]bool{}
		for _, s := range c.scopes() {
			vs := checkScope(t, c, s.name)
			red[s.name] = len(vs) > 0
			t.Logf("scope %-40s red=%v (%d violation(s))", s.name, red[s.name], len(vs))
		}
		if red["full"] {
			t.Error("full: the marker is free there (via " + freeHost + "'s briefing) but the checker is RED")
		}
		if !red["scenario/tutorial-intro"] {
			t.Error("scenario/tutorial-intro: the marker is hint-only there but the checker is GREEN")
		}
		for name, r := range red {
			if name != "scenario/tutorial-intro" && r {
				t.Errorf("%s is RED; only scenario/tutorial-intro (which excludes %s) should be", name, freeHost)
			}
		}
	})
}
