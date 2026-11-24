package catalog_test

// The V39 half of this file (ADR-0056 A3b-5) is at the bottom: the placement rule
// "no evade challenge after an investigate challenge", checked on every scenario
// under scenarios/ and on the no-scenario order, with its negative cases.
//
// Scenario composition guard, I11 half (ADR-0055 (drafting) S1). The pair
// "an evade challenge's forbiddenRules intersect an EARLIER trigger's
// expectedRules" is what makes ADR-0003's attempt scope load-bearing, and it
// depends on the ORDER a scenario puts the challenges in. So the pin table below
// is per scenario, and TestEvadeForbiddenRules_IntersectPriorTriggerExpectedRules
// (catalog_test.go) walks every scenarios/*/scenario.yaml against it. The
// functions here hold the computation and the comparison, so the negative tests
// at the bottom can feed them synthetic input and show each failure mode is red.

import (
	"errors"
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
	// One investigate challenge (50-nimbus-desk-triage) and no evade challenge: nothing
	// to pin, and an evade challenge added to it would have no entry (and would also be
	// refused by V39 if it came after the investigate challenge).
	"ir-nimbus-desk": {},
	// onboarding (ADR-0055 D9) is 00-tutorial alone: a trigger and no evade challenge,
	// so there is no entry to pin. The row is still required (there is no default).
	"onboarding": {},
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

// ---- V39 (ADR-0056 A3b-5): no evade challenge after an investigate challenge ----
//
// Why (ADR-0003 W2, extended to the investigate type by ADR-0056): the evade clean
// gate taints only the CURRENT mission, and an investigate challenge has no forbidden
// rule. A participant who leaves an investigate challenge unsolved keeps it current,
// and while it is, a fire of a rule that a later evade challenge forbids taints nobody
// (ingest/investigate_w2_test.go and scoreboard/investigate_inert_test.go fix that
// behaviour). So a course puts every evade challenge before its first investigate
// challenge. catalog.LoadScored refuses the other order at start-up (checkPlacement);
// the tests below check the real scenarios/ tree with an independent computation, the
// production check on the same input, and each failure mode on a synthetic tree.
//
// There is no investigate challenge under challenges/ yet (A7), so on the real tree
// the rule holds vacuously today: the test is what turns red the day one is added
// after an evade challenge.

// evadesAfterInvestigate is the test's own computation of the rule (not catalog's):
// the evade challenges of order that come after the first investigate challenge.
func evadesAfterInvestigate(cat catalog.Catalog, order []string) ([]string, error) {
	var late []string
	seenInvestigate := false
	for _, cid := range order {
		ch, ok := cat[cid]
		if !ok {
			return nil, fmt.Errorf("order names challenge %q, which is not in the catalog", cid)
		}
		switch ch.Type {
		case catalog.TypeInvestigate:
			seenInvestigate = true
		case catalog.TypeEvade:
			if seenInvestigate {
				late = append(late, cid)
			}
		}
	}
	return late, nil
}

func TestV39_RealTree_NoEvadeChallengeAfterAnInvestigateChallenge(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	scenarios, err := catalog.LoadScenarios("../../scenarios")
	if err != nil {
		t.Fatalf("load scenarios: %v", err)
	}
	if len(scenarios) < 3 {
		t.Fatalf("loaded %d scenarios, want at least 3: the root is wrong or the tree moved", len(scenarios))
	}
	manifests, err := filepath.Glob("../../scenarios/*/scenario.yaml")
	if err != nil || len(manifests) != len(scenarios) {
		t.Fatalf("scenario manifests %v (err %v), want %d, one per loaded scenario", manifests, err, len(scenarios))
	}
	examined := 0
	for _, sc := range scenarios {
		late, err := evadesAfterInvestigate(cat, sc.Challenges)
		if err != nil {
			t.Fatalf("%s: %v", sc.ID, err)
		}
		if len(late) != 0 {
			t.Errorf("scenario %s places evade challenge(s) %v after an investigate challenge (ADR-0003 W2 / ADR-0056 V39)", sc.ID, late)
		}
		examined += len(sc.Challenges)
	}
	if examined == 0 {
		t.Fatal("no challenge of any scenario was examined")
	}
	// the production check, through the door the scoreboard uses, on the same input
	for _, p := range manifests {
		if _, err := catalog.LoadScored("../../challenges", p, ""); err != nil {
			t.Errorf("LoadScored(%s): %v", p, err)
		}
	}
	// and with no scenario: the order is the sorted ids of the whole catalog
	if late, err := evadesAfterInvestigate(cat, cat.IDs()); err != nil || len(late) != 0 {
		t.Errorf("the no-scenario order (sorted ids) places evade challenge(s) %v after an investigate challenge (err %v)", late, err)
	}
	if _, err := catalog.LoadScored("../../challenges", "", ""); err != nil {
		t.Errorf("LoadScored with no scenario: %v", err)
	}
}

// v39Tree writes a synthetic challenges/ tree: one trigger, two evade, two
// investigate challenges. The order of a scenario is the scenario's own.
func v39Tree(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "challenges")
	writeChallenge(t, dir, "01-recon", "type: trigger\nexpectedRules:\n  - \"r1\"\n")
	writeChallenge(t, dir, "02-evade-a", "type: evade\nexpectedFlag: \"FALCO{dev-a}\"\nforbiddenRules:\n  - \"r2\"\n")
	writeChallenge(t, dir, "03-evade-b", "type: evade\nexpectedFlag: \"FALCO{dev-b}\"\nforbiddenRules:\n  - \"r3\"\n")
	writeChallenge(t, dir, "04-ir-a", inv("", evMount(invMount), invHexQ))
	writeChallenge(t, dir, "05-ir-b", inv("", evMount(invMount), invHexQ))
	return dir
}

func TestV39_PlacementRule_EachFailureModeIsRedAndEachControlIsGreen(t *testing.T) {
	chalDir := v39Tree(t)
	cat, err := catalog.Load(chalDir)
	if err != nil {
		t.Fatal(err)
	}
	scnDir := filepath.Join(t.TempDir(), "scenarios")
	cases := []struct {
		name  string
		order []string
		late  []string // the evade challenges after the first investigate challenge; nil = allowed
	}{
		{"evade after an investigate challenge", []string{"01-recon", "04-ir-a", "02-evade-a"}, []string{"02-evade-a"}},
		{"every evade after the first investigate, another investigate between", []string{"04-ir-a", "02-evade-a", "05-ir-b", "03-evade-b"}, []string{"02-evade-a", "03-evade-b"}},
		{"evade directly after the only investigate challenge", []string{"04-ir-a", "03-evade-b"}, []string{"03-evade-b"}},
		{"control: investigate challenge last", []string{"01-recon", "02-evade-a", "03-evade-b", "04-ir-a"}, nil},
		{"control: a trigger and an investigate challenge after the evade ones", []string{"02-evade-a", "04-ir-a", "01-recon", "05-ir-b"}, nil},
		{"control: no investigate challenge", []string{"01-recon", "02-evade-a", "03-evade-b"}, nil},
		{"control: no evade challenge", []string{"04-ir-a", "01-recon", "05-ir-b"}, nil},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := fmt.Sprintf("case-%d", i)
			writeGuardScenario(t, scnDir, name, tc.order...)
			late, err := evadesAfterInvestigate(cat, tc.order)
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(late, tc.late) {
				t.Fatalf("the test's own computation = %v, want %v (the case is mis-written)", late, tc.late)
			}
			scored, err := catalog.LoadScored(chalDir, filepath.Join(scnDir, name, "scenario.yaml"), "")
			if len(tc.late) == 0 {
				if err != nil {
					t.Fatalf("an allowed order was refused: %v", err)
				}
				if !equalStrings(scored.Order, tc.order) {
					t.Fatalf("Order = %v, want the scenario's %v", scored.Order, tc.order)
				}
				return
			}
			if !errors.Is(err, catalog.ErrEvadeAfterInvestigate) {
				t.Fatalf("LoadScored err = %v, want ErrEvadeAfterInvestigate", err)
			}
			for _, cid := range tc.late {
				if !strings.Contains(err.Error(), cid) {
					t.Fatalf("the refusal %q does not name %s", err, cid)
				}
			}
		})
	}
}

// With no scenario the order is the sorted ids, and the same rule applies to it: the
// scoreboard's "current" is defined on that order too (cmd/scoreboard hands
// Scored.Order to both the Grader and the Journey).
func TestV39_PlacementRule_AlsoAppliesToTheNoScenarioOrder(t *testing.T) {
	t.Run("evade sorts after the investigate challenge: refused", func(t *testing.T) {
		dir := t.TempDir()
		writeChallenge(t, dir, "01-ir", inv("", evMount(invMount), invHexQ))
		writeChallenge(t, dir, "02-evade", "type: evade\nexpectedFlag: \"FALCO{dev-a}\"\nforbiddenRules:\n  - \"r2\"\n")
		_, err := catalog.LoadScored(dir, "", "")
		if !errors.Is(err, catalog.ErrEvadeAfterInvestigate) || !strings.Contains(err.Error(), "02-evade") {
			t.Fatalf("LoadScored err = %v, want ErrEvadeAfterInvestigate naming 02-evade", err)
		}
	})
	t.Run("control: evade sorts before the investigate challenge", func(t *testing.T) {
		dir := t.TempDir()
		writeChallenge(t, dir, "00-evade", "type: evade\nexpectedFlag: \"FALCO{dev-a}\"\nforbiddenRules:\n  - \"r2\"\n")
		writeChallenge(t, dir, "01-ir", inv("", evMount(invMount), invHexQ))
		scored, err := catalog.LoadScored(dir, "", "")
		if err != nil {
			t.Fatalf("an allowed order was refused: %v", err)
		}
		if !equalStrings(scored.Order, []string{"00-evade", "01-ir"}) {
			t.Fatalf("Order = %v, want [00-evade 01-ir]", scored.Order)
		}
	})
}
