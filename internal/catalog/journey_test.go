package catalog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

func writeJourney(t *testing.T, dir, name, yaml string) {
	t.Helper()
	cdir := filepath.Join(dir, name)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cdir, "journey.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

func journeyCatalog() catalog.Catalog {
	return catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}, WindowSeconds: 10},
		"05-silent-search": {ID: "05-silent-search", Type: "evade", ExpectedFlag: "FALCO{x}", WindowSeconds: 10},
	}
}

func TestLoadJourneys_ParsesAndKeysByChallengeID(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
tagline: obj
briefing: intro
steps:
  - label: step one
    detail: do the thing
hints:
  - hint one
  - hint two
docsUrl: /missions/01-initial-recon/
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	j, ok := js["01-initial-recon"]
	if !ok {
		t.Fatalf("journey not loaded; got keys %v", js)
	}
	if j.Title != "潜入" || j.Tagline != "obj" || j.Briefing != "intro" {
		t.Fatalf("fields wrong: %+v", j)
	}
	if len(j.Steps) != 1 || j.Steps[0].Label != "step one" || j.Steps[0].Detail != "do the thing" {
		t.Fatalf("steps wrong: %+v", j.Steps)
	}
	if len(j.Hints) != 2 || j.Hints[1] != "hint two" {
		t.Fatalf("hints wrong: %+v", j.Hints)
	}
	if j.DocsURL != "/missions/01-initial-recon/" {
		t.Fatalf("docsUrl wrong: %q", j.DocsURL)
	}
}

func TestLoadJourneys_MissingFileGracefulDegrade(t *testing.T) {
	dir := t.TempDir()
	// Directory exists (a challenge dir) but has no journey.yaml.
	if err := os.MkdirAll(filepath.Join(dir, "01-initial-recon"), 0o755); err != nil {
		t.Fatal(err)
	}
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("missing journey.yaml must not error: %v", err)
	}
	if len(js) != 0 {
		t.Fatalf("expected no journeys, got %d", len(js))
	}
}

func TestLoadJourneys_MissingDirNoError(t *testing.T) {
	js, err := catalog.LoadJourneys(filepath.Join(t.TempDir(), "nope"), journeyCatalog())
	if err != nil {
		t.Fatalf("missing dir must not error: %v", err)
	}
	if len(js) != 0 {
		t.Fatalf("expected empty, got %d", len(js))
	}
}

func TestLoadJourneys_RestrictedOutChallengeIsSkipped(t *testing.T) {
	dir := t.TempDir()
	// RESTRICT-OUT case: a challenge directory whose name (= its id) is not in
	// the active, scenario-restricted catalog. Its declared challengeId MATCHES
	// its directory name (so it is NOT a typo) — it is simply outside the active
	// scenario. It must be silently skipped, not treated as an error, and a
	// valid in-catalog journey alongside it must still load.
	writeJourney(t, dir, "99-ghost", `
challengeId: 99-ghost
title: ghost
`)
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
title: 潜入
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("restricted-out challenge must be skipped, not error: %v", err)
	}
	if _, ok := js["99-ghost"]; ok {
		t.Fatalf("99-ghost is not in the catalog; it must be skipped, got %v", js)
	}
	if _, ok := js["01-initial-recon"]; !ok {
		t.Fatalf("in-catalog journey must still load; got %v", js)
	}
	if len(js) != 1 {
		t.Fatalf("expected exactly 1 journey loaded, got %d: %v", len(js), js)
	}
}

func TestLoadJourneys_ChallengeIDMismatchIsTypoError(t *testing.T) {
	dir := t.TempDir()
	// TYPO case: directory 01-initial-recon (a real, in-catalog challenge) but
	// journey.yaml declares a non-empty challengeId that does NOT match the
	// directory name. This is a content mistake that would silently drop the
	// mission from /journey under the old "is id in cat?" skip; it MUST be a
	// loud error (fail-closed), restoring the pre-tutorial fatal behaviour.
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recom
title: 潜入
`)
	_, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err == nil {
		t.Fatal("challengeId that mismatches its directory name must be a typo error, not a silent skip")
	}
	// The error must name the offending declared id and the directory so the
	// content author can find the typo.
	msg := err.Error()
	if !strings.Contains(msg, "01-initial-recom") || !strings.Contains(msg, "01-initial-recon") {
		t.Fatalf("typo error should name both the declared id and the directory; got: %v", err)
	}
}

func TestLoadJourneys_TypoErrorsEvenInFullCatalog(t *testing.T) {
	dir := t.TempDir()
	// A typo must be loud regardless of whether the catalog is a subset or the
	// full (unrestricted) catalog: skip keys off the directory name, so a full
	// catalog does not launder a mismatching challengeId into a silent load.
	full := catalog.Catalog{
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}, WindowSeconds: 10},
		"01-initial-recom": {ID: "01-initial-recom", Type: "trigger", ExpectedRules: []string{"r"}, WindowSeconds: 10},
	}
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recom
title: 潜入
`)
	if _, err := catalog.LoadJourneys(dir, full); err == nil {
		t.Fatal("typo must error even when the mistyped id happens to exist elsewhere in a full catalog")
	}
}

func TestLoadJourneys_DefaultsChallengeIDToDirName(t *testing.T) {
	dir := t.TempDir()
	// No challengeId field -> defaults to the directory name, which IS in cat.
	writeJourney(t, dir, "05-silent-search", `
title: 静かな探索
`)
	js, err := catalog.LoadJourneys(dir, journeyCatalog())
	if err != nil {
		t.Fatalf("LoadJourneys: %v", err)
	}
	if _, ok := js["05-silent-search"]; !ok {
		t.Fatalf("challengeId should default to dir name; got %v", js)
	}
}

func TestLoadJourneys_TitleRequired(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", `
challengeId: 01-initial-recon
tagline: no title here
`)
	if _, err := catalog.LoadJourneys(dir, journeyCatalog()); err == nil {
		t.Fatal("expected error when title is empty")
	}
}
