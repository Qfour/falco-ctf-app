package catalog_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

func writeNarrative(t *testing.T, path, yaml string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestApplyNarrativeOverrides_ReplacesLocalWholesale proves the ADR-0014
// invariant: when an override exists for a challengeId, the challenge-local
// briefing/bridge is completely ignored (not merged field-by-field) and
// replaced by the override's values.
func TestApplyNarrativeOverrides_ReplacesLocalWholesale(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "03-stealth-read", `
challengeId: 03-stealth-read
title: 静かな読み取り
tagline: obj
briefing: "Mission 02 の前提が入った課題ローカルの文章"
bridge: "次は 04 だ、という課題ローカルの予告"
`)
	cat := catalog.Catalog{
		"03-stealth-read": {ID: "03-stealth-read", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
	js, err := catalog.LoadJourneys(dir, cat)
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}

	n := catalog.Narrative{
		Overrides: map[string]catalog.NarrativeOverride{
			"03-stealth-read": {
				Briefing: "オーバーライド後の中立ブリーフィング",
				Bridge:   "オーバーライド後のブリッジ",
			},
		},
	}
	if err := catalog.ApplyNarrativeOverrides(js, n); err != nil {
		t.Fatalf("ApplyNarrativeOverrides: %v", err)
	}

	got := js["03-stealth-read"]
	if got.Briefing != "オーバーライド後の中立ブリーフィング" {
		t.Fatalf("briefing not replaced: %+v", got)
	}
	if got.Bridge != "オーバーライド後のブリッジ" {
		t.Fatalf("bridge not replaced: %+v", got)
	}
	if strings.Contains(got.Briefing, "Mission 02") || strings.Contains(got.Bridge, "04") {
		t.Fatalf("challenge-local text leaked through override: %+v", got)
	}
	// Fields the override doesn't own must be untouched.
	if got.Title != "静かな読み取り" || got.Tagline != "obj" {
		t.Fatalf("non-overlay fields must survive untouched: %+v", got)
	}
}

// TestApplyNarrativeOverrides_OmittedBridgeIsClearedNotFallback proves the
// "no silent partial merge" invariant from the opposite angle: an override
// entry that only sets briefing (bridge omitted, defaults to "") must NOT
// fall back to the challenge-local bridge — it must clear it, because the
// pair is replaced together.
func TestApplyNarrativeOverrides_OmittedBridgeIsClearedNotFallback(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "03-stealth-read", `
challengeId: 03-stealth-read
title: t
briefing: "local briefing"
bridge: "local bridge that must not survive"
`)
	cat := catalog.Catalog{
		"03-stealth-read": {ID: "03-stealth-read", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
	js, err := catalog.LoadJourneys(dir, cat)
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}

	n := catalog.Narrative{
		Overrides: map[string]catalog.NarrativeOverride{
			"03-stealth-read": {Briefing: "override briefing only"},
		},
	}
	if err := catalog.ApplyNarrativeOverrides(js, n); err != nil {
		t.Fatalf("ApplyNarrativeOverrides: %v", err)
	}
	got := js["03-stealth-read"]
	if got.Bridge != "" {
		t.Fatalf("omitted bridge in override must clear, not fall back to local: got %q", got.Bridge)
	}
}

// TestApplyNarrativeOverrides_NoOverride_ExistingScenariosUnaffected is the
// regression test ADR-0014 Verification item 2 asks for: scenarios that ship
// no narrative.yaml (nimbusbreach-full, tutorial-intro, as of this change)
// must see zero behavior change. A zero-value Narrative (what LoadNarrative
// returns for a missing file) must leave every journey byte-for-byte as
// LoadJourneys produced it.
func TestApplyNarrativeOverrides_NoOverride_ExistingScenariosUnaffected(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "03-stealth-read", `
challengeId: 03-stealth-read
title: 静かな読み取り
briefing: "Mission 02 で正面から /etc/shadow を読んだら盛大に検知された。"
bridge: "次は 04 だ。"
`)
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
briefing: "recon briefing"
`)
	cat := catalog.Catalog{
		"03-stealth-read":  {ID: "03-stealth-read", Type: "evade", ExpectedFlag: "FALCO{x}"},
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
	}
	js, err := catalog.LoadJourneys(dir, cat)
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	before := map[string]catalog.Journey{}
	for k, v := range js {
		before[k] = v
	}

	// Simulate main.go's wiring for a scenario with no narrative.yaml: read
	// a nonexistent path (LoadNarrative degrades to a zero Narrative), then
	// apply it.
	n, err := catalog.LoadNarrative(filepath.Join(t.TempDir(), "narrative.yaml"))
	if err != nil {
		t.Fatalf("LoadNarrative on missing file must not error: %v", err)
	}
	if err := catalog.ApplyNarrativeOverrides(js, n); err != nil {
		t.Fatalf("ApplyNarrativeOverrides with empty overlay must not error: %v", err)
	}

	for id, want := range before {
		got := js[id]
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("journey %q changed with no narrative overlay applied:\nbefore: %+v\nafter:  %+v", id, want, got)
		}
	}
}

// TestLoadNarrative_MissingFileNoError mirrors LoadJourneys/LoadScenario's
// graceful-degrade posture for the common "no narrative.yaml" case.
func TestLoadNarrative_MissingFileNoError(t *testing.T) {
	n, err := catalog.LoadNarrative(filepath.Join(t.TempDir(), "nope", "narrative.yaml"))
	if err != nil {
		t.Fatalf("missing narrative.yaml must not error: %v", err)
	}
	if len(n.Overrides) != 0 {
		t.Fatalf("expected no overrides, got %+v", n)
	}
}

// TestLoadNarrative_MalformedYAMLIsLoud is the content-mistake counterpart:
// a narrative.yaml that fails to parse must be a loud error, not silently
// treated as "no overrides" (same posture as a malformed journey.yaml).
func TestLoadNarrative_MalformedYAMLIsLoud(t *testing.T) {
	p := filepath.Join(t.TempDir(), "narrative.yaml")
	writeNarrative(t, p, "overrides: [this, is, not, a, map]")
	if _, err := catalog.LoadNarrative(p); err == nil {
		t.Fatal("malformed narrative.yaml must error, not silently degrade")
	}
}

// TestApplyNarrativeOverrides_UnknownChallengeIDFailsLoud proves the
// fail-loud requirement: overriding a challengeId that has no corresponding
// entry in the loaded Journeys (never existed, or was restricted out of the
// active scenario) must error, mirroring Catalog.Restrict's "scenario
// references unknown challenge" posture rather than silently doing nothing.
func TestApplyNarrativeOverrides_UnknownChallengeIDFailsLoud(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
`)
	cat := catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
	}
	js, err := catalog.LoadJourneys(dir, cat)
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}

	n := catalog.Narrative{
		Overrides: map[string]catalog.NarrativeOverride{
			"99-ghost": {Briefing: "no such mission"},
		},
	}
	err = catalog.ApplyNarrativeOverrides(js, n)
	if err == nil {
		t.Fatal("override referencing a challengeId absent from Journeys must fail loud")
	}
	if !strings.Contains(err.Error(), "99-ghost") {
		t.Fatalf("error should name the offending challengeId; got: %v", err)
	}
}

// TestApplyNarrativeOverrides_RestrictedOutChallengeIDFailsLoud covers the
// scenario-restriction flavor of the same fail-loud rule: a challenge that
// genuinely exists in challenges/ but was restricted out of the active
// scenario's catalog (so LoadJourneys skipped it) must still be rejected as
// an orphan override, not silently ignored.
func TestApplyNarrativeOverrides_RestrictedOutChallengeIDFailsLoud(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "02-credential-files", `
challengeId: 02-credential-files
title: 認証情報探索
`)
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
`)
	// Active catalog is restricted to 01 only (mirrors tutorial-intro
	// excluding 02) — LoadJourneys skips 02-credential-files as RESTRICT-OUT.
	restricted := catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
	}
	js, err := catalog.LoadJourneys(dir, restricted)
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	if _, ok := js["02-credential-files"]; ok {
		t.Fatal("test setup invariant broken: 02-credential-files should have been restricted out")
	}

	n := catalog.Narrative{
		Overrides: map[string]catalog.NarrativeOverride{
			"02-credential-files": {Briefing: "leftover override for a mission not in this scenario"},
		},
	}
	if err := catalog.ApplyNarrativeOverrides(js, n); err == nil {
		t.Fatal("override for a challenge restricted out of the active scenario must fail loud")
	}
}

// TestTutorialIntroNarrative_ResolvesMission02Contradiction is the ADR-0014
// Verification item 3 proof: it reads the REAL challenges/ and scenarios/
// trees (not fixtures) and confirms that
//
//   - challenges/03-stealth-read/journey.yaml's challenge-local briefing
//     still opens with the "Mission 02" reference (nothing was rewritten in
//     place — the fallback stays exactly as content-engineer will later
//     neutralize it in a separate P27-2 PR),
//   - but scenario `tutorial-intro` (00, 01, 03 — no 02), which ships
//     scenarios/tutorial-intro/narrative.yaml, sees the override text with
//     no "Mission 02" reference once main.go's wiring (LoadScenario ->
//     Restrict -> LoadJourneys -> LoadNarrative -> ApplyNarrativeOverrides)
//     is replayed end-to-end, and
//   - scenario `nimbusbreach-full`, which ships no narrative.yaml, is
//     completely unaffected and keeps the original "Mission 02" briefing
//     (the ADR-0014 Verification item 2 regression, exercised against real
//     content rather than a synthetic fixture).
func TestTutorialIntroNarrative_ResolvesMission02Contradiction(t *testing.T) {
	const mission02Ref = "Mission 02"

	loadScenarioJourneys := func(scenarioPath string) catalog.Journeys {
		t.Helper()
		full, err := catalog.Load("../../challenges")
		if err != nil {
			t.Fatalf("Load real challenges: %v", err)
		}
		sc, err := catalog.LoadScenario(scenarioPath)
		if err != nil {
			t.Fatalf("LoadScenario(%s): %v", scenarioPath, err)
		}
		restricted, err := full.Restrict(sc.Challenges)
		if err != nil {
			t.Fatalf("Restrict(%s): %v", scenarioPath, err)
		}
		journeys, err := catalog.LoadJourneys("../../challenges", restricted)
		if err != nil {
			t.Fatalf("LoadJourneys(%s): %v", scenarioPath, err)
		}
		narrativePath := filepath.Join(filepath.Dir(scenarioPath), "narrative.yaml")
		n, err := catalog.LoadNarrative(narrativePath)
		if err != nil {
			t.Fatalf("LoadNarrative(%s): %v", narrativePath, err)
		}
		if err := catalog.ApplyNarrativeOverrides(journeys, n); err != nil {
			t.Fatalf("ApplyNarrativeOverrides(%s): %v", scenarioPath, err)
		}
		return journeys
	}

	// Sanity check the premise: the challenge-local fallback (as loaded with
	// no restriction/override at all) still contains the contradiction this
	// fixture exists to fix. If content-engineer's later neutralization pass
	// removes it, this assertion (not the override behavior) will need
	// updating — that is the intended coupling.
	full, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("Load real challenges: %v", err)
	}
	baseline, err := catalog.LoadJourneys("../../challenges", full)
	if err != nil {
		t.Fatalf("LoadJourneys baseline: %v", err)
	}
	if !strings.Contains(baseline["03-stealth-read"].Briefing, mission02Ref) {
		t.Fatalf("premise broken: challenges/03-stealth-read/journey.yaml no longer contains %q; "+
			"this fixture's raison d'être (proving override resolves it) needs re-validating", mission02Ref)
	}

	tutorial := loadScenarioJourneys("../../scenarios/tutorial-intro/scenario.yaml")
	if strings.Contains(tutorial["03-stealth-read"].Briefing, mission02Ref) {
		t.Fatalf("tutorial-intro's narrative override must remove the Mission 02 reference; got briefing: %q",
			tutorial["03-stealth-read"].Briefing)
	}

	full1010 := loadScenarioJourneys("../../scenarios/nimbusbreach-full/scenario.yaml")
	if !strings.Contains(full1010["03-stealth-read"].Briefing, mission02Ref) {
		t.Fatalf("nimbusbreach-full ships no narrative.yaml and must keep the original briefing unchanged; got: %q",
			full1010["03-stealth-read"].Briefing)
	}
}
