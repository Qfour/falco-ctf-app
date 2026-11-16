package catalog_test

// Scenario composition guard, I11 half (ADR-0055 (drafting) S1). The pair
// "an evade challenge's forbiddenRules intersect an EARLIER trigger's
// expectedRules" is what makes ADR-0003's attempt scope load-bearing, and it
// depends on the ORDER a scenario puts the challenges in. So the pin table below
// is per scenario, and TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules
// (catalog_test.go) walks every scenarios/*/scenario.yaml against it. The
// functions here hold the computation and the comparison, so the negative tests
// at the bottom can feed them synthetic input and show each failure mode is red.

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// nimbusbreachArcPins is the intersection set of the canonical 01 to 10 arc
// (ADR-0003 C2's "twin mission" structure; the reasoning is on the test in
// catalog_test.go). nimbusbreach-with-tutorial reuses it unchanged because the
// one trigger it adds in front, 00-tutorial, expects "Execution from /dev/shm",
// which no evade challenge in the arc forbids.
var nimbusbreachArcPins = map[string][]string{
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

// evadePins pins, per scenario id and per evade challenge in it, the exact set
// forbiddenRules ∩ (expectedRules of every trigger EARLIER in that scenario's
// order). A nil value is an explicit "no shared fire". There is no default: a
// scenario with no row, an evade challenge with no entry, and an entry for a
// challenge that is not an evade challenge of the scenario all fail, so a new
// scenario or a reordering cannot take a shared fire past review silently.
//
// A pair that crosses scenarios (a challenge pinned in one scenario because
// ANOTHER scenario's order changes what comes before it) is not special: each
// scenario is its own row, because the order is the scenario's. Adding a row
// is the deliberate act; ADR-0003 section A1 (attempt scope still exempts the
// shared required fire) is what the author confirms when doing it.
var evadePins = map[string]map[string][]string{
	"nimbusbreach-full":          nimbusbreachArcPins,
	"nimbusbreach-with-tutorial": nimbusbreachArcPins,
	// 00-tutorial ("Execution from /dev/shm") and 01-initial-recon ("Contact K8S
	// API Server From Container") come before the only evade challenge, 03, which
	// forbids only "Read sensitive file untrusted": no shared fire.
	"tutorial-intro": {"03-stealth-read": nil},
}

// evadeIntersections returns, for every evade challenge named in order, the
// sorted, de-duplicated set forbiddenRules ∩ (expectedRules of every trigger
// challenge earlier in order). A challenge in order that is not in cat is an
// error (Restrict refuses it at startup, so the scenario is already broken).
func evadeIntersections(cat catalog.Catalog, order []string) (map[string][]string, error) {
	out := make(map[string][]string)
	priorExpected := make(map[string]struct{})
	for _, cid := range order {
		ch, ok := cat[cid]
		if !ok {
			return nil, fmt.Errorf("scenario names challenge %q, which is not in the catalog", cid)
		}
		switch ch.Type {
		case "evade":
			var got []string
			for _, r := range ch.ForbiddenRules {
				if _, shared := priorExpected[r]; shared {
					got = append(got, r)
				}
			}
			slices.Sort(got)
			out[cid] = slices.Compact(got)
		case "trigger":
			for _, r := range ch.ExpectedRules {
				priorExpected[r] = struct{}{}
			}
		}
	}
	return out, nil
}

// diffEvadePins compares one scenario's computed intersections with pins and
// returns one line per problem; empty means the scenario matches its pins.
func diffEvadePins(scenarioID string, got map[string][]string, pins map[string]map[string][]string) []string {
	want, ok := pins[scenarioID]
	if !ok {
		return []string{fmt.Sprintf("scenario %q has no row in evadePins: add one (a nil entry per evade challenge means no shared fire)", scenarioID)}
	}
	var problems []string
	for _, cid := range slices.Sorted(maps.Keys(got)) {
		w, pinned := want[cid]
		if !pinned {
			problems = append(problems, fmt.Sprintf("%s/%s: evade challenge has no entry in evadePins (computed %v)", scenarioID, cid, got[cid]))
			continue
		}
		w = slices.Clone(w)
		slices.Sort(w)
		if !equalStrings(got[cid], w) {
			problems = append(problems, fmt.Sprintf("%s/%s: forbiddenRules ∩ prior expectedRules = %v, pinned %v "+
				"(ADR-0003 attempt scope must keep this pair exempt: update the pin only after confirming it still exempts the shared required fire)",
				scenarioID, cid, got[cid], w))
		}
	}
	for _, cid := range slices.Sorted(maps.Keys(want)) {
		if _, present := got[cid]; !present {
			problems = append(problems, fmt.Sprintf("%s/%s: pinned, but the scenario has no such evade challenge (stale pin, or a reorder/removal dropped it)", scenarioID, cid))
		}
	}
	return problems
}

// guardCatalog is a synthetic catalog: 01-recon (trigger, expects "r1"),
// 02-evade (evade, forbids "r1" and "r2"), 03-other (trigger, expects "r2").
func guardCatalog() catalog.Catalog {
	return catalog.Catalog{
		"01-recon": {ID: "01-recon", Type: "trigger", ExpectedRules: []string{"r1"}},
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r1", "r2"}, ExpectedFlag: "FALCO{dev-02}"},
		"03-other": {ID: "03-other", Type: "trigger", ExpectedRules: []string{"r2"}},
	}
}

func TestEvadeIntersections_DependsOnOrder(t *testing.T) {
	cat := guardCatalog()
	cases := []struct {
		name  string
		order []string
		want  []string
	}{
		{"one earlier trigger shares a rule", []string{"01-recon", "02-evade"}, []string{"r1"}},
		{"both triggers earlier", []string{"01-recon", "03-other", "02-evade"}, []string{"r1", "r2"}},
		{"evade first: nothing earlier, no shared fire", []string{"02-evade", "01-recon", "03-other"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evadeIntersections(cat, tc.order)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := got["02-evade"]; !present {
				t.Fatalf("02-evade missing from %v: the evade challenge was not examined", got)
			}
			if !equalStrings(got["02-evade"], tc.want) {
				t.Fatalf("got %v, want %v", got["02-evade"], tc.want)
			}
		})
	}
	if _, err := evadeIntersections(cat, []string{"01-recon", "99-missing"}); err == nil {
		t.Fatal("expected an error for a scenario naming a challenge that is not in the catalog")
	}
}

// Negative tests: each failure mode of the pin comparison is red, and the
// matching control is green (so the comparison is not simply always red).
func TestDiffEvadePins_NegativeCases(t *testing.T) {
	got := map[string][]string{"02-evade": {"r1"}}
	cases := []struct {
		name    string
		pins    map[string]map[string][]string
		wantBad string // substring of a problem; "" = no problem expected
	}{
		{"control: pinned exactly", map[string]map[string][]string{"demo": {"02-evade": {"r1"}}}, ""},
		{"intersection not pinned (nil pin, computed r1)", map[string]map[string][]string{"demo": {"02-evade": nil}}, "pinned []"},
		{"pin names a rule that is not shared", map[string]map[string][]string{"demo": {"02-evade": {"r1", "r2"}}}, "pinned [r1 r2]"},
		{"scenario has no row", map[string]map[string][]string{"other": {"02-evade": {"r1"}}}, `has no row in evadePins`},
		{"evade challenge has no entry", map[string]map[string][]string{"demo": {}}, "has no entry in evadePins"},
		{"stale pin for a challenge the scenario lacks", map[string]map[string][]string{"demo": {"02-evade": {"r1"}, "09-gone": nil}}, "stale pin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := diffEvadePins("demo", got, tc.pins)
			if tc.wantBad == "" {
				if len(problems) != 0 {
					t.Fatalf("control was reported: %v", problems)
				}
				return
			}
			if len(problems) == 0 {
				t.Fatal("expected a problem, got none")
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.wantBad) {
				t.Fatalf("problems %v do not contain %q", problems, tc.wantBad)
			}
		})
	}
}

// writeGuardScenario writes <root>/<name>/scenario.yaml with the given ordered
// challenges. Fixtures stay under t.TempDir(); the real scenarios/ tree is
// never touched.
func writeGuardScenario(t *testing.T, root, name string, challenges ...string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\ntitle: %s\nchallenges:\n", name, name)
	for _, c := range challenges {
		fmt.Fprintf(&b, "  - %s\n", c)
	}
	if err := os.WriteFile(filepath.Join(dir, "scenario.yaml"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// End to end on a synthetic tree, through the same calls the real test makes
// (catalog.Load, catalog.LoadScenarios, evadeIntersections, diffEvadePins): a
// second scenario whose intersection is not pinned is red even though the first
// scenario matches its pins, and pinning it turns the tree green.
func TestEvadePins_EveryScenarioInTheTreeIsChecked(t *testing.T) {
	dir := t.TempDir()
	chalDir := filepath.Join(dir, "challenges")
	writeChallenge(t, chalDir, "01-recon", "challengeId: \"01-recon\"\ntype: trigger\nexpectedRules:\n  - \"r1\"\n")
	writeChallenge(t, chalDir, "02-evade", "challengeId: \"02-evade\"\ntype: evade\nforbiddenRules:\n  - \"r1\"\nexpectedFlag: \"FALCO{dev-02}\"\n")
	scnDir := filepath.Join(dir, "scenarios")
	writeGuardScenario(t, scnDir, "alpha", "02-evade", "01-recon") // evade first: no shared fire
	writeGuardScenario(t, scnDir, "beta", "01-recon", "02-evade")  // trigger first: shares r1

	cat, err := catalog.Load(chalDir)
	if err != nil {
		t.Fatal(err)
	}
	scenarios, err := catalog.LoadScenarios(scnDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) != 2 {
		t.Fatalf("loaded %d scenarios, want 2", len(scenarios))
	}
	check := func(pins map[string]map[string][]string) []string {
		var all []string
		for _, sc := range scenarios {
			got, err := evadeIntersections(cat, sc.Challenges)
			if err != nil {
				t.Fatalf("%s: %v", sc.ID, err)
			}
			all = append(all, diffEvadePins(sc.ID, got, pins)...)
		}
		return all
	}

	unpinnedBeta := map[string]map[string][]string{"alpha": {"02-evade": nil}, "beta": {"02-evade": nil}}
	problems := check(unpinnedBeta)
	if len(problems) != 1 || !strings.Contains(problems[0], "beta/02-evade") {
		t.Fatalf("want exactly one problem, on beta/02-evade (alpha matches its pin); got %v", problems)
	}
	pinned := map[string]map[string][]string{"alpha": {"02-evade": nil}, "beta": {"02-evade": {"r1"}}}
	if problems := check(pinned); len(problems) != 0 {
		t.Fatalf("fully pinned tree was reported: %v", problems)
	}
}
