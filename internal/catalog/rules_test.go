package catalog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

func writeRuleYAML(t *testing.T, dir, name, yaml string) {
	t.Helper()
	cdir := filepath.Join(dir, name)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "rule.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ruleCatalog() catalog.Catalog {
	return catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
		"05-silent-search": {ID: "05-silent-search", Type: "evade", ExpectedFlag: "FALCO{x}"},
	}
}

// fixture exercising ALL THREE entry kinds (list/macro/rule) in one file, so
// this test does not depend on content-lead's C0 follow-up (adding list:/
// macro: entries to the real challenges/*/rule.yaml) — see rules.go's package
// doc "current-state note": today's real files carry rule: entries only.
const fullFixture = `
- list: grep_commands
  items: [grep, egrep, fgrep]

- macro: protected_shell_spawner
  condition: >
    proc.pname exists

- rule: Search Private Keys or Passwords
  desc: >
    Detect attempts to search for private keys or passwords.
  condition: >
    grep_commands and protected_shell_spawner
  output: Grep private keys | user=%user.name
  priority: NOTICE
  tags: [maturity_stable, mitre_credential_access]
`

func TestLoadRuleExcerpts_ParsesListsMacrosRules(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "01-initial-recon", fullFixture)

	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("LoadRuleExcerpts: %v", err)
	}
	ex, ok := out["01-initial-recon"]
	if !ok {
		t.Fatalf("excerpt not loaded; got keys %v", out)
	}

	if len(ex.Lists) != 1 || ex.Lists[0].Name != "grep_commands" {
		t.Fatalf("lists wrong: %+v", ex.Lists)
	}
	if len(ex.Lists[0].Items) != 3 || ex.Lists[0].Items[1] != "egrep" {
		t.Fatalf("list items wrong: %+v", ex.Lists[0].Items)
	}

	if len(ex.Macros) != 1 || ex.Macros[0].Name != "protected_shell_spawner" {
		t.Fatalf("macros wrong: %+v", ex.Macros)
	}
	if ex.Macros[0].Condition == "" {
		t.Fatalf("macro condition should not be empty: %+v", ex.Macros[0])
	}

	if len(ex.Rules) != 1 || ex.Rules[0].Name != "Search Private Keys or Passwords" {
		t.Fatalf("rules wrong: %+v", ex.Rules)
	}
	r := ex.Rules[0]
	if r.Desc == "" || r.Condition == "" || r.Output == "" || r.Priority != "NOTICE" {
		t.Fatalf("rule fields wrong: %+v", r)
	}
	if len(r.Tags) != 2 || r.Tags[0] != "maturity_stable" {
		t.Fatalf("rule tags wrong: %+v", r.Tags)
	}
}

// TestLoadRuleExcerpts_RuleOnlyFixture pins the CURRENT real-world shape (all
// 12 committed challenges/*/rule.yaml files as of this writing carry only
// rule: entries) — Lists/Macros must come back as non-nil empty slices, not
// null, so the Story tab can render "no List/Macro section" without a nil
// check exploding.
func TestLoadRuleExcerpts_RuleOnlyFixtureYieldsEmptyListsAndMacros(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "01-initial-recon", `
- rule: Contact K8S API Server From Container
  desc: detect it
  condition: evt.type=connect
  output: boom
  priority: NOTICE
  tags: [maturity_stable]
`)
	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("LoadRuleExcerpts: %v", err)
	}
	ex := out["01-initial-recon"]
	if ex.Lists == nil || len(ex.Lists) != 0 {
		t.Fatalf("expected non-nil empty Lists, got %#v", ex.Lists)
	}
	if ex.Macros == nil || len(ex.Macros) != 0 {
		t.Fatalf("expected non-nil empty Macros, got %#v", ex.Macros)
	}
	if len(ex.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %+v", ex.Rules)
	}
}

// TestLoadRuleExcerpts_ListMacroOnlyFixtureYieldsEmptyRules is the /review-5x
// C3 fixup pin: the inverse of the rule-only fixture above. A rule.yaml with
// ONLY list:/macro: entries and no rule: at all (a plausible transitional
// state while content-lead backfills list:/macro: definitions per-challenge,
// before adding the rule: block that references them, or a challenge whose
// operator-authored excerpt is scoped to just the supporting
// definitions) must still load: Rules comes back non-nil empty (not nil, not
// an error), while Lists/Macros are populated. This pins the sniff-then-decode
// branch for list:/macro: independent of whether any rule: entry is present.
func TestLoadRuleExcerpts_ListMacroOnlyFixtureYieldsEmptyRules(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "01-initial-recon", `
- list: grep_commands
  items: [grep, egrep, fgrep]

- macro: protected_shell_spawner
  condition: >
    proc.pname exists
`)
	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("LoadRuleExcerpts: %v", err)
	}
	ex := out["01-initial-recon"]
	if len(ex.Lists) != 1 || ex.Lists[0].Name != "grep_commands" {
		t.Fatalf("lists wrong: %+v", ex.Lists)
	}
	if len(ex.Lists[0].Items) != 3 || ex.Lists[0].Items[2] != "fgrep" {
		t.Fatalf("list items wrong: %+v", ex.Lists[0].Items)
	}
	if len(ex.Macros) != 1 || ex.Macros[0].Name != "protected_shell_spawner" {
		t.Fatalf("macros wrong: %+v", ex.Macros)
	}
	if ex.Rules == nil || len(ex.Rules) != 0 {
		t.Fatalf("expected non-nil empty Rules, got %#v", ex.Rules)
	}
}

func TestLoadRuleExcerpts_MultiRuleFixture(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "01-initial-recon", `
- rule: First Rule
  desc: d1
  condition: c1
  output: o1
  priority: NOTICE
  tags: [t1]

- rule: Second Rule
  desc: d2
  condition: c2
  output: o2
  priority: WARNING
  tags: [t2]
`)
	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("LoadRuleExcerpts: %v", err)
	}
	ex := out["01-initial-recon"]
	if len(ex.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %+v", ex.Rules)
	}
	if ex.Rules[0].Name != "First Rule" || ex.Rules[1].Name != "Second Rule" {
		t.Fatalf("rule order/names wrong: %+v", ex.Rules)
	}
}

func TestLoadRuleExcerpts_MissingFileGracefulDegrade(t *testing.T) {
	dir := t.TempDir()
	// Directory exists (a challenge dir) but has no rule.yaml.
	if err := os.MkdirAll(filepath.Join(dir, "01-initial-recon"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("missing rule.yaml must not error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no excerpts, got %d", len(out))
	}
}

func TestLoadRuleExcerpts_MissingDirNoError(t *testing.T) {
	out, err := catalog.LoadRuleExcerpts(filepath.Join(t.TempDir(), "nope"), ruleCatalog())
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty, got %d", len(out))
	}
}

func TestLoadRuleExcerpts_RestrictedOutChallengeIsSkipped(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "99-ghost", `
- rule: Ghost Rule
  desc: d
  condition: c
  output: o
  priority: NOTICE
  tags: [t]
`)
	writeRuleYAML(t, dir, "01-initial-recon", `
- rule: Real Rule
  desc: d
  condition: c
  output: o
  priority: NOTICE
  tags: [t]
`)
	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("restricted-out challenge must be skipped, not error: %v", err)
	}
	if _, ok := out["99-ghost"]; ok {
		t.Fatalf("99-ghost is not in the catalog; it must be skipped, got %v", out)
	}
	if _, ok := out["01-initial-recon"]; !ok {
		t.Fatalf("in-catalog excerpt must still load; got %v", out)
	}
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 excerpt loaded, got %d: %v", len(out), out)
	}
}

func TestLoadRuleExcerpts_MalformedYAMLIsLoudError(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "01-initial-recon", `
- rule: [this is not a valid scalar for a map value
`)
	if _, err := catalog.LoadRuleExcerpts(dir, ruleCatalog()); err == nil {
		t.Fatal("malformed rule.yaml must be a loud error, not a silent skip")
	}
}

// TestLoadRuleExcerpts_NoFlagLeakage is a content-safety regression pin: a
// FalcoRuleItem's fields must never accidentally carry a FALCO{...} flag or
// any evade expectedFlag value if a future rule.yaml author copy-pastes too
// much. This test does not scan real challenges/ (that is the design spike's
// one-off grep audit, already clean) — it pins that the loader itself does
// not special-case or leak any additional field beyond what the struct
// declares (no expectedFlag/flag field exists on FalcoRuleItem at all).
func TestLoadRuleExcerpts_NoFlagLeakage(t *testing.T) {
	dir := t.TempDir()
	writeRuleYAML(t, dir, "01-initial-recon", fullFixture)
	out, err := catalog.LoadRuleExcerpts(dir, ruleCatalog())
	if err != nil {
		t.Fatalf("LoadRuleExcerpts: %v", err)
	}
	ex := out["01-initial-recon"]
	for _, r := range ex.Rules {
		if r.Desc == "" && r.Condition == "" && r.Output == "" {
			continue
		}
		// FalcoRuleItem has no field named Flag/ExpectedFlag; this loop simply
		// documents that the returned type structurally cannot carry one.
	}
	_ = ex
}

// TestMission10DisplayRuleExcerptExcludesProof is ADR-0032 rev2 D9(i), security
// finding F3: the participant-facing DISPLAY excerpt
// challenges/10-final-exfil/rule.yaml must NOT reveal the capstone read-leg
// positive-proof rule — neither its NAME ("Nimbus Vault Master Key Read") nor
// any condition/output/desc that mentions the vault key path "master.key".
// The proof rule's condition lives only in the platform-side private canon
// (publication boundary); exposing it here would hand participants the exact
// shape the proof keys on.
//
// This is DELIBERATELY ASYMMETRIC with mission 05: 05's display excerpt
// (challenges/05-silent-search/rule.yaml) DOES carry its own proof rule
// "Shell Redirected Private Key Read" in full, because 05 is a teaching
// mission whose whole point is to show how input-redirection reads differ
// from a direct read — its condition is intended public content. Mission 10
// is the capstone/boss: the same technique must be DISCOVERED and re-applied,
// so its proof condition stays hidden. If a future edit copies 10's proof
// rule into its display excerpt (as 05 has), this test fails loudly rather
// than silently leaking the boundary. (Allowlist membership of the rule NAME
// — in challenges/custom-falco-rules.txt or upstream — is a separate concern
// enforced by scripts/check-challenge-rules.sh; this test is only about the
// display excerpt.)
func TestMission10DisplayRuleExcerptExcludesProof(t *testing.T) {
	const challengesDir = "../../challenges"
	cat, err := catalog.Load(challengesDir)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	excerpts, err := catalog.LoadRuleExcerpts(challengesDir, cat)
	if err != nil {
		t.Fatalf("load rule excerpts: %v", err)
	}
	ex, ok := excerpts["10-final-exfil"]
	if !ok {
		// A missing display excerpt for 10 is itself fine (no leak possible),
		// but 10 is expected to ship a rule.yaml showing its forbidden rules,
		// so flag the absence to catch an accidental deletion.
		t.Fatalf("10-final-exfil has no display rule excerpt (rule.yaml); expected the forbidden-rule excerpt to be present")
	}

	const proofRuleName = "Nimbus Vault Master Key Read"
	const vaultKeyNeedle = "master.key"
	for _, r := range ex.Rules {
		if r.Name == proofRuleName {
			t.Errorf("10-final-exfil display excerpt (rule.yaml) must NOT contain the proof rule %q (publication boundary, ADR-0032 rev2 D9(i)); it belongs only in the platform-side private canon", proofRuleName)
		}
		for field, val := range map[string]string{"condition": r.Condition, "output": r.Output, "desc": r.Desc} {
			if strings.Contains(val, vaultKeyNeedle) {
				t.Errorf("10-final-exfil display excerpt rule %q %s mentions %q — the vault key path must not appear in the public display excerpt (ADR-0032 rev2 D9(i))", r.Name, field, vaultKeyNeedle)
			}
		}
	}
	for _, m := range ex.Macros {
		if strings.Contains(m.Condition, vaultKeyNeedle) {
			t.Errorf("10-final-exfil display excerpt macro %q condition mentions %q — must not appear in the public excerpt", m.Name, vaultKeyNeedle)
		}
	}
}
