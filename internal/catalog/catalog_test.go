package catalog_test

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

func writeChallenge(t *testing.T, dir, name, yaml string) {
	t.Helper()
	cdir := filepath.Join(dir, name)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "falco-rule.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_Empty(t *testing.T) {
	dir := t.TempDir()
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cat) != 0 {
		t.Fatalf("expected empty catalog, got %d entries", len(cat))
	}
}

func TestLoad_MissingDir_NoError(t *testing.T) {
	cat, err := catalog.Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing dir should not error, got: %v", err)
	}
	if len(cat) != 0 {
		t.Fatalf("expected empty catalog, got %d entries", len(cat))
	}
}

func TestLoad_TriggerChallenge(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "01-read-shadow", `
challengeId: "01-read-shadow"
type: trigger
expectedRules:
  - "Read sensitive file untrusted"
`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := cat["01-read-shadow"]
	if !ok {
		t.Fatal("challenge not loaded")
	}
	if ch.Type != "trigger" {
		t.Errorf("type: got %q, want trigger", ch.Type)
	}
	if len(ch.ExpectedRules) != 1 || ch.ExpectedRules[0] != "Read sensitive file untrusted" {
		t.Errorf("expectedRules: %v", ch.ExpectedRules)
	}
}

func TestLoad_EvadeChallenge(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "02-evade", `
challengeId: "02-evade"
type: evade
forbiddenRules:
  - "Read sensitive file untrusted"
expectedFlag: "FALCO{abc}"
`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ch := cat["02-evade"]
	if ch.Type != "evade" || ch.ExpectedFlag != "FALCO{abc}" {
		t.Errorf("got %+v", ch)
	}
}

func TestLoad_TypeRequired(t *testing.T) {
	dir := t.TempDir()
	// no `type:` field — must return an error (inference was removed)
	writeChallenge(t, dir, "a", `expectedRules: ["X"]`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for missing type:, got nil")
	}
}

func TestLoad_UnknownTypeError(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "a", `type: unknown
expectedRules: ["X"]`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for unknown type value, got nil")
	}
}

func TestLoad_InvalidFlag(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "bad-flag", `
type: evade
expectedFlag: "invalid-flag-format"
`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid expectedFlag format, got nil")
	}
}

// TestLoad_RequireExpectedRuleFire_LoadsAndValidates is ADR-0008 Decision (3):
// a positive-proof evade challenge loads with RequireExpectedRuleFire set and
// its expectedRules populated.
func TestLoad_RequireExpectedRuleFire_LoadsAndValidates(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "05-silent-search", `
challengeId: "05-silent-search"
type: evade
forbiddenRules:
  - "Search Private Keys or Passwords"
expectedRules:
  - "Shell Redirected Private Key Read"
requireExpectedRuleFire: true
expectedFlag: "FALCO{abc}"
`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ch := cat["05-silent-search"]
	if !ch.RequireExpectedRuleFire {
		t.Fatal("requireExpectedRuleFire must load as true")
	}
	if len(ch.ExpectedRules) != 1 || ch.ExpectedRules[0] != "Shell Redirected Private Key Read" {
		t.Errorf("expectedRules: %v", ch.ExpectedRules)
	}
}

// TestLoad_RequireExpectedRuleFire_RequiresExpectedRules is ADR-0008 Decision
// (3)'s load-time validation: a positive-proof gate with nothing to prove
// (empty expectedRules) would be unsatisfiable by construction, mirroring the
// existing trigger-type validation (TestLoad_TypeRequired's sibling).
func TestLoad_RequireExpectedRuleFire_RequiresExpectedRules(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "bad", `
type: evade
requireExpectedRuleFire: true
expectedFlag: "FALCO{abc}"
`)
	_, err := catalog.Load(dir)
	if err == nil {
		t.Fatal("expected error for requireExpectedRuleFire=true with empty expectedRules, got nil")
	}
}

func TestLoad_IDFallbackToDirName(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "07-no-id", `type: trigger
expectedRules: ["Z"]`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cat["07-no-id"]; !ok {
		t.Fatalf("expected id to fall back to directory name; got keys: %v", cat.IDs())
	}
}

func TestLoad_SkipsDirsWithoutFalcoRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "empty-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) != 0 {
		t.Errorf("expected empty, got %d", len(cat))
	}
}

func TestIDs_Sorted(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "03-c", `type: trigger
expectedRules: ["a"]`)
	writeChallenge(t, dir, "01-a", `type: trigger
expectedRules: ["a"]`)
	writeChallenge(t, dir, "02-b", `type: trigger
expectedRules: ["a"]`)
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := cat.IDs()
	want := []string{"01-a", "02-b", "03-c"}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("IDs[%d]: got %q, want %q", i, id, want[i])
		}
	}
}

// --- detect challenges: capture-path resolution (resolveCapture) ------------
//
// resolveCapture is unexported; it is exercised through Load → validateDetect,
// which is exactly how it runs in production (fail-fast at boot on a bad
// catalog). detectYAML builds a detect challenge with the given capture paths.
func detectYAML(evasion, benign string) string {
	return `challengeId: 04-detect
type: detect
detect:
  evasionCapture: ` + evasion + `
  benignCapture: ` + benign + `
  ruleName: participant_detect
  allowedMacros:
    - open_read
`
}

func TestLoad_Detect_ValidRelativePaths(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "04-detect", detectYAML("detect/evasion.scap", "./detect/benign.scap"))
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("valid detect challenge must load: %v", err)
	}
	ch := cat["04-detect"]
	if ch.Type != "detect" || ch.Detect == nil {
		t.Fatalf("detect challenge not loaded: %+v", ch)
	}
	// Cleaned relative, forward-slash, no leading "./".
	if ch.Detect.EvasionCapturePath != "detect/evasion.scap" {
		t.Errorf("evasion path: got %q, want detect/evasion.scap", ch.Detect.EvasionCapturePath)
	}
	if ch.Detect.BenignCapturePath != "detect/benign.scap" {
		t.Errorf("benign path (leading ./ must be cleaned): got %q, want detect/benign.scap", ch.Detect.BenignCapturePath)
	}
}

func TestLoad_Detect_RejectsBadCapturePaths(t *testing.T) {
	// Each case is a single offending path (paired with a valid other path) that
	// resolveCapture must reject at load time.
	cases := map[string]struct{ evasion, benign string }{
		"empty":       {"", "detect/benign.scap"},
		"absolute":    {"/etc/shadow", "detect/benign.scap"},
		"dotdot":      {"../../../etc/shadow", "detect/benign.scap"},
		"dotdot-mid":  {"detect/../../secret.scap", "detect/benign.scap"},
		"dot-only":    {".", "detect/benign.scap"},
		"benign-bad":  {"detect/evasion.scap", "../escape.scap"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeChallenge(t, dir, "04-detect", detectYAML(c.evasion, c.benign))
			if _, err := catalog.Load(dir); err == nil {
				t.Fatalf("case %q: expected load error for bad capture path, got nil", name)
			}
		})
	}
}

func TestLoad_Detect_RejectsFlagAndRules(t *testing.T) {
	dir := t.TempDir()
	// A detect challenge is not flag/live-Falco based; expectedFlag or
	// expected/forbiddenRules must be rejected.
	writeChallenge(t, dir, "04-detect", `challengeId: 04-detect
type: detect
expectedFlag: "FALCO{x}"
detect:
  evasionCapture: detect/evasion.scap
  benignCapture: detect/benign.scap
`)
	if _, err := catalog.Load(dir); err == nil {
		t.Fatal("detect challenge with expectedFlag must be rejected")
	}
}

func TestLoad_Detect_MissingDetectBlock(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "04-detect", "challengeId: 04-detect\ntype: detect\n")
	if _, err := catalog.Load(dir); err == nil {
		t.Fatal("detect challenge without a detect block must be rejected")
	}
}

// TestLoad_RealChallenges verifies the production challenges/ tree parses
// cleanly. Pins the CTF Company 10-mission core storyline (01–10, canonical
// order: recon → cred access → evade → harvest → RCE → persist → C2 → hide →
// exfil boss) plus the 00-tutorial 0問目, the 11-cloud-cred-hunt bonus
// (#46 cloud-threat-detection MVP), the 12-cover-tracks bonus (P27-4
// ATT&CK expansion — Defense Evasion / T1070.002, upstream default rule
// "Clear Log Activities", no custom rule), and the 13-archive-loot bonus
// (ADR-0017 — Collection / T1560.001, project's 2nd customRules addition
// after mission05/ADR-0008: "Archive Collected Data"). The detect-authoring
// twin (03-stealth-read-detect) lands in Phase 44.2 with its captures; the
// detect engine ships here (44.0) without a live challenge, so the
// attack-mission count stays at 10.
//
// The tutorial is a real trigger challenge so it exercises the normal solve
// path, but it is deliberately EXCLUDED from the scored scenario
// (nimbusbreach-full) so it never affects the scoring denominator. That
// contract is asserted in TestScoredScenario_ExcludesTutorial below — keep the
// two in sync: adding a challenge here that should be scored must also be added
// to scenarios/nimbusbreach-full/scenario.yaml. The 11-cloud-cred-hunt,
// 12-cover-tracks, and 13-archive-loot bonuses are likewise not part of the
// nimbusbreach-full scenario (each launched standalone).
func TestLoad_RealChallenges(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("failed to load real challenges: %v", err)
	}
	want := []string{
		"00-tutorial",
		"01-initial-recon",
		"02-credential-files",
		"03-stealth-read",
		"04-key-search",
		"05-silent-search",
		"06-web-rce-shell",
		"07-persist",
		"08-c2-beacon",
		"09-hidden-cache",
		"10-final-exfil",
		"11-cloud-cred-hunt",
		"12-cover-tracks",
		"13-archive-loot",
	}
	ids := cat.IDs()
	if len(ids) != len(want) {
		t.Fatalf("expected %d challenges, got %d: %v", len(want), len(ids), ids)
	}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("IDs[%d]: got %q, want %q", i, id, want[i])
		}
	}
}

// TestScoredScenario_ExcludesTutorial pins the scoring-non-impact contract for
// the 00-tutorial 0問目: the production scored scenario (nimbusbreach-full) must
// select exactly the 10 scored missions and must NOT include 00-tutorial. The
// scoreboard runs with SCENARIO_FILE pinned to this scenario, so Restrict
// (fail-closed) drops the tutorial from scoring, /api/state, totals and the
// leaderboard. If this fails the tutorial has leaked into the scored set.
func TestScoredScenario_ExcludesTutorial(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	sc, err := catalog.LoadScenario("../../scenarios/nimbusbreach-full/scenario.yaml")
	if err != nil {
		t.Fatalf("load scored scenario: %v", err)
	}
	scored, err := cat.Restrict(sc.Challenges)
	if err != nil {
		t.Fatalf("restrict to scored scenario: %v", err)
	}
	if _, leaked := scored["00-tutorial"]; leaked {
		t.Fatal("scoring leak: 00-tutorial is present in the scored scenario nimbusbreach-full")
	}
	if len(scored) != 10 {
		t.Fatalf("scored scenario must stay at 10 challenges, got %d: %v", len(scored), scored.IDs())
	}
}

// TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules is ADR-0003
// Verification (a)'s catalog-side contract test — "the required condition for
// I11's candidate promotion". It reads the REAL challenges/ tree and the REAL
// nimbusbreach-full scenario order (not a synthetic fixture) and, for every
// evade challenge in the scored progression, computes:
//
//	forbiddenRules ∩ (expectedRules of every trigger challenge EARLIER in the
//	                   progression order)
//
// A NON-EMPTY intersection is normal and expected (ADR-0003 C2's "twin
// mission" structure: 02's required rule fire IS 03's forbidden rule; same
// for 04/05, and 10 forbids all seven of 01/02/04/06/07/08/09's expected
// rules). The test's job is not to assert emptiness — it is to PIN the exact
// pairs so a future PR cannot silently reintroduce PR #124's regression (a
// persistent taint gate with no attempt scope permanently blocks every one of
// these evade missions for every regular participant, because clearing the
// preceding trigger REQUIRES firing the very rule the evade forbids). Adding
// a new challenge that changes this intersection must fail here until the
// author confirms attempt scope (ADR-0003 §A1) still exempts the shared fire
// and updates `want` below.
func TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	sc, err := catalog.LoadScenario("../../scenarios/nimbusbreach-full/scenario.yaml")
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	order := sc.Challenges

	want := map[string][]string{
		"03-stealth-read":  {"Read sensitive file untrusted"},
		"05-silent-search": {"Search Private Keys or Passwords"},
		"10-final-exfil": {
			"Contact K8S API Server From Container",
			"Create Hardlink Over Sensitive Files",
			"Drop and execute new binary in container",
			"Read sensitive file untrusted",
			"Redirect STDOUT/STDIN to Network Connection in Container",
			"Run shell untrusted",
			"Search Private Keys or Passwords",
		},
	}

	checked := 0
	for i, cid := range order {
		ch, ok := cat[cid]
		if !ok || ch.Type != "evade" {
			continue
		}
		priorExpected := make(map[string]struct{})
		for _, priorID := range order[:i] {
			if p, ok := cat[priorID]; ok && p.Type == "trigger" {
				for _, r := range p.ExpectedRules {
					priorExpected[r] = struct{}{}
				}
			}
		}
		var got []string
		for _, r := range ch.ForbiddenRules {
			if _, ok := priorExpected[r]; ok {
				got = append(got, r)
			}
		}
		sort.Strings(got)
		w := append([]string(nil), want[cid]...)
		sort.Strings(w)
		if !equalStrings(got, w) {
			t.Errorf("%s: forbiddenRules ∩ prior expectedRules = %v, want %v "+
				"(ADR-0003 attempt scope must keep this pair exempt — update this pin only "+
				"after confirming attempt scope still exempts the shared required fire)", cid, got, w)
		}
		checked++
	}
	if checked != len(want) {
		t.Fatalf("expected to check exactly %d evade challenges (%v), checked %d — a scenario reorder "+
			"or challenge removal may have dropped one of the pinned pairs", len(want), want, checked)
	}
}

// TestCustomFalcoRules_EachNameOwnedByExactlyOneChallenge is ADR-0032 D9 (f)
// ("the proof rule name is not shared with any other challenge"), applied in
// one table to EVERY project-specific Falco rule name in
// challenges/custom-falco-rules.txt (the customRules allowlist, ADR-0008
// Decision (5)) — so the next customRules entry adds a row here instead of a
// 4th copy-pasted test. It replaces, name for name and with the same checks,
// the retired TestExpectedRuleFire_NewRuleNameUniqueToMission05 (ADR-0008
// Verification (c)), TestExpectedRuleFire_NewRuleNameUniqueToMission13
// (ADR-0017 Verification (b)) and TestExpectedRuleFire_NewRuleNameUniqueToMission10
// (ADR-0032 S2); an ADR that still cites one of those names means this test.
//
// Why a customRules name must have exactly one owner: scoring.Grader's
// positive-proof write records a fire for EVERY evade challenge that lists
// the rule in expectedRules with requireExpectedRuleFire set (it is not
// keyed on which mission is current), so a proof rule shared with a second
// challenge would let one mission's fire count as the other's proof, or
// taint it if the second lists it as forbidden. Trigger owners (13) carry
// no proof write, but the allowlist line and platform's deploy-order note
// (contract table, "Falco custom rule override" row) are written for one
// mission each, and a second consumer would make them wrong silently.
//
// Checked for each name (all four were checked by the retired tests too,
// except that 05's requireExpectedRuleFire is now pinned as well):
//  1. the allowlist and the table below name the same set: a new allowlist
//     line fails here until its owner is declared, and a removed line fails
//     until its row is dropped (no silent gap in either direction);
//  2. exactly one challenge references the name in expectedRules ∪
//     forbiddenRules, and that challenge is the declared owner;
//  3. the owner lists it in expectedRules (its success / proof signal,
//     never a forbidden rule);
//  4. the owner's requireExpectedRuleFire is the declared value (05 and 10
//     gate their solve on the proof; 13 is a trigger).
//
// Allowlist membership against upstream (that the name is NOT an upstream
// rule) is a separate concern, enforced by scripts/check-challenge-rules.sh.
func TestCustomFalcoRules_EachNameOwnedByExactlyOneChallenge(t *testing.T) {
	const challengesDir = "../../challenges"
	owners := map[string]struct {
		owner        string
		requireProof bool
	}{
		"Shell Redirected Private Key Read": {owner: "05-silent-search", requireProof: true},
		"Archive Collected Data":            {owner: "13-archive-loot", requireProof: false},
		"Nimbus Vault Master Key Read":      {owner: "10-final-exfil", requireProof: true},
	}

	raw, err := os.ReadFile(filepath.Join(challengesDir, "custom-falco-rules.txt"))
	if err != nil {
		t.Fatalf("read customRules allowlist: %v", err)
	}
	// Same parse as scripts/check-challenge-rules.sh: skip blank lines and
	// lines whose first non-blank character is '#', strip trailing blanks.
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name := strings.TrimRight(line, " \t\r")
		if slices.Contains(names, name) {
			t.Errorf("custom-falco-rules.txt lists %q twice", name)
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		t.Fatal("parsed 0 rule names from custom-falco-rules.txt — the parse is broken, not the allowlist empty")
	}

	// (1) allowlist set == table key set, both directions.
	for _, name := range names {
		if _, ok := owners[name]; !ok {
			t.Errorf("custom-falco-rules.txt lists %q but this test declares no owner for it — add a row (ADR-0032 D9 (f): one owning challenge per customRules name)", name)
		}
	}
	for name := range owners {
		if !slices.Contains(names, name) {
			t.Errorf("this test declares an owner for %q but custom-falco-rules.txt no longer lists it — drop the row", name)
		}
	}

	cat, err := catalog.Load(challengesDir)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	for _, name := range names {
		want, ok := owners[name]
		if !ok {
			continue // already reported by (1)
		}
		t.Run(name, func(t *testing.T) {
			// (2) exactly one referencing challenge, and it is the owner.
			var referencing []string
			for _, cid := range cat.IDs() {
				ch := cat[cid]
				if slices.Contains(ch.ExpectedRules, name) || slices.Contains(ch.ForbiddenRules, name) {
					referencing = append(referencing, cid)
				}
			}
			if len(referencing) != 1 || referencing[0] != want.owner {
				t.Fatalf("%q must appear in exactly one challenge's expectedRules/forbiddenRules (%s), found in %v",
					name, want.owner, referencing)
			}
			ch := cat[want.owner]
			// (3) it is the owner's expectedRule, not a forbiddenRule.
			if !slices.Contains(ch.ExpectedRules, name) {
				t.Fatalf("%s must list %q in expectedRules, got expectedRules=%v forbiddenRules=%v",
					want.owner, name, ch.ExpectedRules, ch.ForbiddenRules)
			}
			// (4) the proof gate is wired exactly as declared.
			if ch.RequireExpectedRuleFire != want.requireProof {
				t.Fatalf("%s requireExpectedRuleFire = %v, want %v", want.owner, ch.RequireExpectedRuleFire, want.requireProof)
			}
		})
	}
}

// equalStrings compares two possibly-nil string slices for equal contents in
// order (both inputs are pre-sorted by the caller). A tiny local helper so
// this file does not need to pull in "slices" solely for this one test.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
