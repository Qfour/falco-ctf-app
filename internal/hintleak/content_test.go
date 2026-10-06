package hintleak_test

// content_test.go assembles hintleak.Input for each scope from the REAL
// challenges/ and scenarios/ trees (ADR-0026 D5-1 / D5-5). Free-display items
// come from the production call sequence — catalog.LoadScored -> LoadJourneys
// -> LoadNarrative + ApplyNarrativeOverrides -> LoadRuleExcerpts
// (cmd/scoreboard/main.go) — so what is counted as "free" is what a participant
// is actually shown, not what happens to be in a file. It is shared by the V5
// test (fixtures_test.go) and the V6 mutation tests (hintleak_test.go), which
// mutate a COPY of the tracked files in a temp dir and run the same loader.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

// scopeData is one evaluation scope ("full" or "scenario/<name>").
type scopeData struct {
	name      string
	ids       []string        // challenges in scope
	overrides map[string]bool // ids whose briefing/bridge the scenario's narrative.yaml replaces
	in        hintleak.Input
}

func (s scopeData) has(id string) bool {
	for _, x := range s.ids {
		if x == id {
			return true
		}
	}
	return false
}

// repoData is every scope of one tree.
type repoData struct {
	root         string
	scopes       []scopeData
	fixtureCount int // fixture files scanned (the same set in every scope)
}

func (r repoData) scope(t *testing.T, name string) scopeData {
	t.Helper()
	for _, s := range r.scopes {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("scope %q not found", name)
	return scopeData{}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	// Not a Skip: a scan that silently covers nothing is exactly the failure
	// mode V5 exists to prevent (ADR-0026 V5: "走査 0 件は fail").
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s: %v", root, err)
	}
	return root
}

// trackedFiles lists the files under dir (relative to root, slash-separated).
// In a git checkout it is `git ls-files` — the same reference as the image
// check (V1) — so an untracked/ignored file (.DS_Store) is not scanned. Where
// there is no .git (the Dockerfile.test copy), it walks the files on disk.
func trackedFiles(t *testing.T, root, dir string) []string {
	t.Helper()
	var out []string
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		cmd := exec.Command("git", "-C", root, "-c", "core.quotepath=off", "ls-files", "-z", "--", dir)
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("git ls-files %s: %v", dir, err)
		}
		for _, p := range bytes.Split(b, []byte{0}) {
			if len(p) > 0 {
				out = append(out, string(p))
			}
		}
	} else {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				rel, _ := filepath.Rel(root, p)
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(out)
	return out
}

var fixturePathRE = regexp.MustCompile(`^challenges/[^/]+/fixtures/.+`)

func readFixtures(t *testing.T, root string) []hintleak.Item {
	t.Helper()
	var items []hintleak.Item
	for _, rel := range trackedFiles(t, root, "challenges") {
		if !fixturePathRE.MatchString(rel) {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("fixture %s is not a regular file (symlink/special/missing): %v", rel, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		items = append(items, hintleak.Item{Source: strings.TrimPrefix(rel, "challenges/"), Text: string(b)})
	}
	return items
}

// ruleItems turns the DISPLAYED parts of a parsed rule.yaml (what the Story
// tab's Falco Rule panel shows) into free items. Comments and unknown keys in
// the file are not shown, so they are not free.
func ruleItems(id string, ex catalog.FalcoRuleExcerpt) []hintleak.Item {
	var out []hintleak.Item
	add := func(what, text string) {
		out = append(out, hintleak.Item{Source: id + " rule.yaml " + what, Text: text})
	}
	for _, r := range ex.Rules {
		add("rule "+r.Name+" name", r.Name)
		add("rule "+r.Name+" desc", r.Desc)
		add("rule "+r.Name+" condition", r.Condition)
		add("rule "+r.Name+" output", r.Output)
		add("rule "+r.Name+" priority", r.Priority)
		for _, tag := range r.Tags {
			add("rule "+r.Name+" tag", tag)
		}
	}
	for _, m := range ex.Macros {
		add("macro "+m.Name+" name", m.Name)
		add("macro "+m.Name+" condition", m.Condition)
	}
	for _, l := range ex.Lists {
		add("list "+l.Name+" name", l.Name)
		for _, it := range l.Items {
			add("list "+l.Name+" item", it)
		}
	}
	return out
}

// loadScope runs the production sequence for one scope (scenarioFile "" = the
// full catalog) and assembles the D5-1 inputs.
func loadScope(t *testing.T, chalDir, name, scenarioFile string, fixtures []hintleak.Item) scopeData {
	t.Helper()
	scored, err := catalog.LoadScored(chalDir, scenarioFile, "")
	if err != nil {
		t.Fatalf("scope %s: catalog.LoadScored: %v", name, err)
	}
	cat := scored.Catalog
	for _, id := range cat.IDs() {
		if cat[id].Dir() != id {
			t.Fatalf("challenge %q lives in directory %q: challengeId must equal the directory name (journeys are keyed by directory, so it would silently drop out of this check)", id, cat[id].Dir())
		}
	}
	journeys, err := catalog.LoadJourneys(chalDir, cat)
	if err != nil {
		t.Fatalf("scope %s: catalog.LoadJourneys: %v", name, err)
	}
	overrides := map[string]bool{}
	if scenarioFile != "" {
		nar, err := catalog.LoadNarrative(filepath.Join(filepath.Dir(scenarioFile), "narrative.yaml"))
		if err != nil {
			t.Fatalf("scope %s: catalog.LoadNarrative: %v", name, err)
		}
		// D5-1: a narrative override REPLACES the briefing (never appends).
		if err := catalog.ApplyNarrativeOverrides(journeys, nar); err != nil {
			t.Fatalf("scope %s: catalog.ApplyNarrativeOverrides: %v", name, err)
		}
		for id := range nar.Overrides {
			overrides[id] = true
		}
	}
	excerpts, err := catalog.LoadRuleExcerpts(chalDir, cat)
	if err != nil {
		t.Fatalf("scope %s: catalog.LoadRuleExcerpts: %v", name, err)
	}

	ids := scored.Order
	in := hintleak.Input{Targets: fixtures}
	for _, id := range ids {
		if j, ok := journeys[id]; ok {
			for i, h := range j.Hints {
				in.Hints = append(in.Hints, hintleak.Item{Source: fmt.Sprintf("%s hints[%d]", id, i+1), Text: h.Text})
			}
			// Free = what is shown without paying: briefing, step label/detail
			// (and rule.yaml below). title / tagline / bridge are deliberately NOT
			// free (D5-1: the strict side).
			in.Free = append(in.Free, hintleak.Item{Source: id + " briefing", Text: j.Briefing})
			for i, st := range j.Steps {
				in.Free = append(in.Free,
					hintleak.Item{Source: fmt.Sprintf("%s steps[%d].label", id, i+1), Text: st.Label},
					hintleak.Item{Source: fmt.Sprintf("%s steps[%d].detail", id, i+1), Text: st.Detail})
			}
		}
		in.Free = append(in.Free, ruleItems(id, excerpts[id])...)
	}
	return scopeData{name: name, ids: ids, overrides: overrides, in: in}
}

// loadRepo builds every scope (full + each scenarios/*/scenario.yaml, D5-5) of
// the tree at root.
func loadRepo(t *testing.T, root string) repoData {
	t.Helper()
	chalDir := filepath.Join(root, "challenges")
	fixtures := readFixtures(t, root)
	r := repoData{root: root, fixtureCount: len(fixtures)}
	r.scopes = append(r.scopes, loadScope(t, chalDir, "full", "", fixtures))
	manifests, err := filepath.Glob(filepath.Join(root, "scenarios", "*", "scenario.yaml"))
	if err != nil {
		t.Fatalf("glob scenarios: %v", err)
	}
	sort.Strings(manifests)
	for _, m := range manifests {
		r.scopes = append(r.scopes, loadScope(t, chalDir, "scenario/"+filepath.Base(filepath.Dir(m)), m, fixtures))
	}
	return r
}

// check runs hintleak.Check on one scope.
func check(t *testing.T, r repoData, name string) []hintleak.Violation {
	t.Helper()
	vs, err := hintleak.Check(r.scope(t, name).in)
	if err != nil {
		t.Fatalf("scope %s: hintleak.Check: %v", name, err)
	}
	return vs
}

// --- mutation helpers: edit a COPY of the tracked files, then run the real loader ---

// copyRepo copies the tracked challenges/ and scenarios/ files into a temp dir.
func copyRepo(t *testing.T) string {
	t.Helper()
	src := repoRoot(t)
	dst := t.TempDir()
	for _, dir := range []string{"challenges", "scenarios"} {
		for _, rel := range trackedFiles(t, src, dir) {
			b, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			writeFile(t, filepath.Join(dst, filepath.FromSlash(rel)), b)
		}
	}
	return dst
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(b, []byte(text)...))
}

// editJourney rewrites <root>/challenges/<id>/journey.yaml after fn edits it.
func editJourney(t *testing.T, root, id string, fn func(*catalog.Journey)) {
	t.Helper()
	p := filepath.Join(root, "challenges", id, "journey.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var j catalog.Journey
	if err := yaml.Unmarshal(b, &j); err != nil {
		t.Fatalf("parse %s: %v", p, err)
	}
	fn(&j)
	out, err := yaml.Marshal(&j)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, out)
}

func addHint(j *catalog.Journey, text string) {
	j.Hints = append(j.Hints, catalog.JourneyHint{Kind: "solution", Text: text})
}

func addFixture(t *testing.T, root, relUnderChallenges, text string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "challenges", filepath.FromSlash(relUnderChallenges)), []byte(text))
}

// describe renders violations for a failure message: one line per target.
func describe(vs []hintleak.Violation) string {
	byTarget := map[string][]string{}
	for _, v := range vs {
		byTarget[v.Target] = append(byTarget[v.Target], fmt.Sprintf("%q (hint: %s)", v.Gram, strings.Join(v.HintSources, ", ")))
	}
	var lines []string
	for f, gs := range byTarget {
		lines = append(lines, fmt.Sprintf("  %s: %d distinct n-gram(s), first %s", f, len(gs), gs[0]))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
