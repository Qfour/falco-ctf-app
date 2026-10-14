package hintleak_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

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

	t.Run("an invisible format character (Unicode Cf) in a hint or target is an error", func(t *testing.T) {
		// Cf is not White_Space, so a ZWSP between two runes of a copied run would
		// split every window across it and let the copy through silently. Refuse
		// instead. (The normalisation itself still removes only White_Space.)
		for _, r := range []rune{0x200B, 0xFEFF, 0x00AD, 0x2060, 0x200D} {
			cf := string(r)
			inHint := hintleak.Input{Hints: one("B hints[1]", "abcde"+cf+"fghijklm"), Targets: one("A/fixtures/f", "abcdefghijklm")}
			inTarget := hintleak.Input{Hints: one("B hints[1]", "abcdefghijklm"), Targets: one("A/fixtures/f", "abcde"+cf+"fghijklm")}
			for name, in := range map[string]hintleak.Input{"hint": inHint, "target": inTarget} {
				_, err := hintleak.Check(in)
				if !errors.Is(err, hintleak.ErrFormatChar) {
					t.Errorf("U+%04X in a %s: err = %v, want ErrFormatChar", r, name, err)
				} else if want := fmt.Sprintf("U+%04X", r); !strings.Contains(err.Error(), want) {
					t.Errorf("U+%04X in a %s: error does not name the code point: %v", r, name, err)
				}
			}
		}
		// Free items are not subject to the rule (they only ever REMOVE violations).
		free := hintleak.Input{Hints: one("B hints[1]", "abcdefghijklm"), Free: one("A briefing", "x\u200by"), Targets: one("A/fixtures/f", "abcdefghijklm")}
		if _, err := hintleak.Check(free); err != nil {
			t.Errorf("Cf in a free item: err = %v, want none", err)
		}
	})

	// --- replicas of the real tree --------------------------------------------
	// Each case edits a COPY of the tracked files (copyRepo) and runs the real
	// loaders (loadRepo), so the loader sequence itself is under test.
	controlRoot := copyRepo(t)
	control := loadRepo(t, controlRoot)

	t.Run("replica: unmutated copy is green in every scope (control)", func(t *testing.T) {
		for _, s := range control.scopes {
			if vs := check(t, control, s.name); len(vs) > 0 {
				t.Fatalf("scope %s is not clean before any mutation:\n%s", s.name, describe(vs))
			}
		}
	})

	// redSet runs every scope and returns the names that are RED.
	redSet := func(t *testing.T, r repoData) map[string]bool {
		t.Helper()
		red := map[string]bool{}
		for _, s := range r.scopes {
			vs := check(t, r, s.name)
			red[s.name] = len(vs) > 0
			t.Logf("scope %-40s red=%v (%d violation(s))", s.name, red[s.name], len(vs))
		}
		return red
	}
	// wantRed fails unless red == the expected set (derived from the manifests),
	// and unless the expectation itself is non-trivial (some RED and some GREEN).
	wantRed := func(t *testing.T, r repoData, red map[string]bool, expect func(scopeData) bool, why string, needGreen bool) {
		t.Helper()
		nRed, nGreen := 0, 0
		for _, s := range r.scopes {
			exp := expect(s)
			if exp {
				nRed++
			} else {
				nGreen++
			}
			if red[s.name] != exp {
				t.Errorf("scope %s: red=%v, want %v (%s)", s.name, red[s.name], exp, why)
			}
		}
		if nRed == 0 || (needGreen && nGreen == 0) {
			t.Fatalf("content の前提が変わった: the expectation derived from the manifests is trivial (%d RED / %d GREEN scopes) — this case no longer tests anything (%s)", nRed, nGreen, why)
		}
	}
	normalize := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, s)
	}

	t.Run("replica: 02's expected answer (14 runes) mixed into a fixture is RED", func(t *testing.T) {
		const id, answer = "02-credential-files", "cat /etc/shadow"
		root := copyRepo(t)
		r := loadRepo(t, root)
		full := r.scope(t, "full")
		// Preconditions: the answer really is a hint, and it is not free text.
		hinted := false
		for _, h := range full.in.Hints {
			if h.Source == id+" hints[3]" && strings.Contains(h.Text, answer) {
				hinted = true
			}
		}
		if !hinted {
			t.Fatalf("content の前提が変わった: %s hints[3] no longer carries the expected answer %q", id, answer)
		}
		for _, f := range full.in.Free {
			if strings.Contains(normalize(f.Text), normalize(answer)) {
				t.Fatalf("content の前提が変わった: the answer %q now appears in free-display text %s", answer, f.Source)
			}
		}
		addFixture(t, root, "01-initial-recon/fixtures/MUTATION.txt", "手順メモ\n  "+answer+"\n")
		vs := check(t, loadRepo(t, root), "full")
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
		const marker, hintHost, freeHost = "scope-marker-7f3a-sentence-alpha-beta", "01-initial-recon", "04-key-search"
		root := copyRepo(t)
		editJourney(t, root, hintHost, func(j *catalog.Journey) { addHint(j, "追加ヒント: "+marker) })
		editJourney(t, root, freeHost, func(j *catalog.Journey) { j.Briefing += "\n" + marker })
		addFixture(t, root, "13-archive-loot/fixtures/MUTATION.txt", marker)
		r := loadRepo(t, root)
		// RED where the marker is a hint but freeHost's (non-overridden) briefing is not shown.
		wantRed(t, r, redSet(t, r), func(s scopeData) bool {
			return s.has(hintHost) && !(s.has(freeHost) && !s.overrides[freeHost])
		}, "hint host in scope, free host's briefing not shown", true)
	})

	t.Run("replica: a narrative override REPLACES the briefing (does not append) — RED only where it overrides", func(t *testing.T) {
		const marker, id = "override-marker-5d21-sentence-gamma-delta", "02-credential-files"
		root := copyRepo(t)
		editJourney(t, root, id, func(j *catalog.Journey) {
			j.Briefing += "\n" + marker
			addHint(j, "追加ヒント: "+marker)
		})
		addFixture(t, root, "13-archive-loot/fixtures/MUTATION.txt", marker)
		r := loadRepo(t, root)
		// Base briefing carries the marker (free) — unless a scenario's narrative replaces it.
		wantRed(t, r, redSet(t, r), func(s scopeData) bool { return s.has(id) && s.overrides[id] },
			"02 in scope and its briefing replaced by the scenario narrative", true)
	})

	for _, field := range []string{"title", "tagline", "bridge"} {
		t.Run("replica: "+field+" is NOT free-display text — RED in every scope that has the mission", func(t *testing.T) {
			const id = "01-initial-recon"
			marker := "field-marker-3c9e-" + field + "-sentence-epsilon"
			root := copyRepo(t)
			editJourney(t, root, id, func(j *catalog.Journey) {
				switch field {
				case "title":
					j.Title += " " + marker
				case "tagline":
					j.Tagline += " " + marker
				case "bridge":
					j.Bridge += " " + marker
				}
				addHint(j, "追加ヒント: "+marker)
			})
			addFixture(t, root, "13-archive-loot/fixtures/MUTATION.txt", marker)
			r := loadRepo(t, root)
			red := redSet(t, r)
			// The marker is only in title/tagline/bridge + a hint: RED wherever the mission is in scope.
			// (A scope without it has no such hint, so it is GREEN; derive both from the manifests.)
			wantRed(t, r, red, func(s scopeData) bool { return s.has(id) }, field+" must not count as free text", false)
		})
	}

	t.Run("replica: text only in a rule.yaml COMMENT is not free; text in a displayed rule field is", func(t *testing.T) {
		const id = "01-initial-recon"
		for _, tc := range []struct {
			name, marker, ruleYAML string
			wantRed                bool
		}{
			{"comment only", "comment-marker-8b41-sentence-zeta-eta", "\n# {M}\n", true},
			{"displayed desc", "desc-marker-6a07-sentence-theta-iota",
				"\n- rule: Hygiene Test Rule\n  desc: {M}\n  condition: evt.type = open\n  output: x\n  priority: INFO\n", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				root := copyRepo(t)
				appendFile(t, filepath.Join(root, "challenges", id, "rule.yaml"), strings.ReplaceAll(tc.ruleYAML, "{M}", tc.marker))
				editJourney(t, root, id, func(j *catalog.Journey) { addHint(j, "追加ヒント: "+tc.marker) })
				addFixture(t, root, "13-archive-loot/fixtures/MUTATION.txt", tc.marker)
				r := loadRepo(t, root)
				for _, s := range r.scopes {
					if !s.has(id) {
						continue
					}
					if got := len(check(t, r, s.name)) > 0; got != tc.wantRed {
						t.Errorf("scope %s: red=%v, want %v", s.name, got, tc.wantRed)
					}
				}
			})
		}
	})

	t.Run("replica: a hint sentence in a NESTED fixture path is RED via the real loader", func(t *testing.T) {
		const marker, id = "nested-marker-1e55-sentence-kappa-lambda", "02-credential-files"
		root := copyRepo(t)
		editJourney(t, root, id, func(j *catalog.Journey) { addHint(j, "追加ヒント: "+marker) })
		addFixture(t, root, id+"/fixtures/a/b/x.txt", marker)
		r := loadRepo(t, root)
		if r.fixtureCount != control.fixtureCount+1 {
			t.Fatalf("fixture files scanned = %d, want %d (the nested file must be picked up)", r.fixtureCount, control.fixtureCount+1)
		}
		vs := check(t, r, "full")
		if len(vs) == 0 || vs[0].Target != id+"/fixtures/a/b/x.txt" {
			t.Fatalf("nested fixture not detected; violations=%d\n%s", len(vs), describe(vs))
		}
	})
}
