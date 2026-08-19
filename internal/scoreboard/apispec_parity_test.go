package scoreboard_test

// ADR-0005 parity tests for the scoreboard binary: this file is the
// software-engineer-owned "make test" gate that keeps
// docs/openapi-scoreboard.yaml honest against the ACTUAL registered route
// table (scoreboard.Handler.Routes(), which is table-driven per-package —
// see internal/apispec/route.go and each sub-package's Routes() method).
//
// V1 (route-set bidirectional match), V3 (origin-guard parity),
// the ADR-0003 A2-2 reset-dirty dedicated assert, V5 (response field-set
// parity for Journey/Me/State/SubmitFlagVerdict), and a REAL-fixture mutation
// proof for V8 all live here. The generic algorithm-level V8 mutation proof
// (synthetic fixtures, no server) lives in internal/apispec/parity_test.go;
// this file additionally proves the SAME mutation classes are caught when
// applied to today's real spec + real route table, not just hand-built data.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

func loadScoreboardSpec(t *testing.T) *apispec.Spec {
	t.Helper()
	spec, err := apispec.LoadSpec(filepath.Join("..", "..", "docs", "openapi-scoreboard.yaml"))
	if err != nil {
		t.Fatalf("load docs/openapi-scoreboard.yaml: %v", err)
	}
	return spec
}

// specFixture is a dedicated ADR-0005 V5 fixture: a 3-mission catalog
// (one trigger to unlock progression, one plain evade, one exfil-required
// evade) with journey content (steps + hints) on the trigger mission so the
// Journey/MissionDetail nested checks (detail, detail.hints, missions[],
// steps[]) all have non-empty content to compare, not just empty arrays.
type specFixture struct {
	t   *testing.T
	srv *scoreboard.Handler
}

const specFixtureOrigin = "https://scoreboard.ctf.local"
const specFixtureAdmin = "admin@ctf.local"

func newSpecFixture(t *testing.T) *specFixture {
	t.Helper()
	cat := catalog.Catalog{
		"01-recon": {ID: "01-recon", Type: "trigger", ExpectedRules: []string{"Recon Rule"}},
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"Forbidden Rule"}, ExpectedFlag: "FALCO{ok}"},
		"03-boss": {
			ID: "03-boss", Type: "evade", ForbiddenRules: []string{"Forbidden Rule"},
			ExpectedFlag: "FALCO{boss}", RequireExfil: true,
		},
	}
	journeys := catalog.Journeys{
		"01-recon": {
			ChallengeID: "01-recon", Title: "偵察", Tagline: "obj-1", Briefing: "brief-1",
			Steps:  []catalog.JourneyStep{{Label: "s0", Detail: "d0"}, {Label: "s1", Detail: "d1"}},
			Hints:  []string{"h1", "h2"},
			Bridge: "bridge-1",
		},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "apispec.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder([]string{"01-recon", "02-evade", "03-boss"}),
		scoreboard.WithAdminEmails([]string{specFixtureAdmin}),
		scoreboard.WithAllowedOrigins([]string{specFixtureOrigin}),
	)
	return &specFixture{t: t, srv: srv}
}

func (f *specFixture) do(method, target, email string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	r.Header.Set("Origin", specFixtureOrigin)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func (f *specFixture) decodedJSON(w *httptest.ResponseRecorder) map[string]any {
	f.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("decode JSON: %v (body=%s)", err, w.Body)
	}
	return m
}

// falcoFire posts one falco event, attributed to user, that fires rule —
// same request shape falcoEventBody (server_test.go, same package) builds,
// duplicated minimally here so this file has no cross-file helper
// dependency beyond the standard fixture pattern.
func (f *specFixture) falcoFire(rule, user string) {
	f.t.Helper()
	w := f.do("POST", "/falco/events", "", map[string]any{
		"rule": rule,
		"output_fields": map[string]any{
			"k8s.ns.name":                "ctf-" + user,
			"k8s.pod.name":               "workspace",
			"container.image.repository": "docker.io/falco-ctf/challenge",
		},
	})
	if w.Code != http.StatusOK {
		f.t.Fatalf("falco fire %s/%s: status=%d body=%s", rule, user, w.Code, w.Body)
	}
}

func (f *specFixture) submit(cid, user, flag string) map[string]any {
	f.t.Helper()
	w := f.do("POST", "/api/challenges/"+cid+"/submit", "", map[string]any{"user": user, "flag": flag})
	if w.Code != http.StatusOK {
		f.t.Fatalf("submit %s/%s: status=%d body=%s", cid, user, w.Code, w.Body)
	}
	return f.decodedJSON(w)
}

// --- V1 ----------------------------------------------------------------

func TestAPISpec_V1_RouteSetMatchesSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	routes := f.srv.Routes()

	// ADR-0005 V8-2: a silently-empty extraction must not read as "no diff".
	if len(routes) == 0 {
		t.Fatal("scoreboard.Handler.Routes() returned zero routes — extraction is broken, not clean")
	}
	specOps := spec.Operations()
	if len(specOps) == 0 {
		t.Fatal("docs/openapi-scoreboard.yaml parsed to zero operations — spec loading is broken, not clean")
	}

	specOnly, implOnly := apispec.RouteSetDiff(specOps, routes)
	if len(specOnly) > 0 {
		t.Errorf("documented but not implemented: %v", specOnly)
	}
	if len(implOnly) > 0 {
		t.Errorf("implemented but undocumented: %v", implOnly)
	}
	// Pinning the known-good count guards against a same-size swap (one
	// route removed, a different one added) that RouteSetDiff alone,
	// summed over set difference, could theoretically mask if both diffs
	// happened to cancel out in length only — they can't cancel in
	// CONTENT (set diff is exact), but this extra count assert costs
	// nothing and matches ADR-0005 C1's real-world count (20 routes).
	if len(routes) != 20 {
		t.Errorf("expected 20 registered routes (ADR-0005 C1), got %d: %v", len(routes), routes)
	}
}

// --- V3 (+ the CollectorForward impl-vs-spec parity extension) ---------

// TestAPISpec_V3_OriginGuardParity is ADR-0005 V3. It also checks
// x-ctf-collector-forward impl-vs-spec parity using the SAME generic
// BoolExtParity primitive — this second check is NOT one of ADR-0005's
// enumerated V1-V8 items; it is a scope decision made during
// implementation (see the PR report) on the grounds that Route already
// carries CollectorForward for exactly this reason (V2's mandatory-field
// list) and the check is a zero-cost reuse of V3's own mechanism.
func TestAPISpec_V3_OriginGuardParity(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	routes := f.srv.Routes()
	specOps := spec.Operations()

	missingKey, onlyImpl, onlySpec := apispec.BoolExtParity(specOps, routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
	if len(missingKey) > 0 {
		t.Errorf("x-ctf-origin-guard key missing on spec operations: %v", missingKey)
	}
	if len(onlyImpl) > 0 {
		t.Errorf("Route.OriginGuarded=true but spec says false/absent: %v", onlyImpl)
	}
	if len(onlySpec) > 0 {
		t.Errorf("spec x-ctf-origin-guard=true but Route.OriginGuarded=false: %v", onlySpec)
	}

	var guarded []string
	for _, rt := range routes {
		if rt.OriginGuarded {
			guarded = append(guarded, rt.MuxPattern())
		}
	}
	// ADR-0005 Decision 4's documented current-truth count.
	if len(guarded) != 7 {
		t.Errorf("expected 7 origin-guarded routes (ADR-0005 Decision 4), got %d: %v", len(guarded), guarded)
	}

	missingKey, onlyImpl, onlySpec = apispec.BoolExtParity(specOps, routes, "x-ctf-collector-forward", func(rt apispec.Route) bool { return rt.CollectorForward })
	if len(missingKey) > 0 {
		t.Errorf("x-ctf-collector-forward key missing on spec operations: %v", missingKey)
	}
	if len(onlyImpl) > 0 {
		t.Errorf("Route.CollectorForward=true but spec says false/absent: %v", onlyImpl)
	}
	if len(onlySpec) > 0 {
		t.Errorf("spec x-ctf-collector-forward=true but Route.CollectorForward=false: %v", onlySpec)
	}
	var forwarded []string
	for _, rt := range routes {
		if rt.CollectorForward {
			forwarded = append(forwarded, rt.MuxPattern())
		}
	}
	if len(forwarded) != 3 {
		t.Errorf("expected 3 collector-forwarded scoreboard routes (ADR-0005 Decision 1), got %d: %v", len(forwarded), forwarded)
	}
}

// --- V4's dedicated ADR-0003 A2-2 assert (scoreboard side) --------------

func TestAPISpec_V4_ResetDirtyNeverForwarded(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	specOps := spec.Operations()
	routes := f.srv.Routes()

	if got := apispec.ResetDirtySpecViolation(specOps); got != "" {
		t.Error(got)
	}
	if got := apispec.ResetDirtyRouteViolation(routes); got != "" {
		t.Error(got)
	}
	// Sanity: the route must actually exist and be reachable at the pattern
	// this check hardcodes — otherwise both violations above would be
	// vacuously "" because ResetDirtyPattern never matched anything.
	found := false
	for _, rt := range routes {
		if rt.MuxPattern() == apispec.ResetDirtyPattern {
			found = true
		}
	}
	if !found {
		t.Fatalf("apispec.ResetDirtyPattern %q matched no registered route — the dedicated A2-2 assert is vacuous", apispec.ResetDirtyPattern)
	}
}

// --- V5 ------------------------------------------------------------------

func TestAPISpec_V5_JourneyFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	// Open one hint and check one step so detail.hints.opened[] and steps[]
	// both carry real content, not just an empty-but-present array.
	if w := f.do("POST", "/api/users/alice/challenges/01-recon/hints/1", "alice@ctf.local", nil); w.Code != http.StatusOK {
		t.Fatalf("open hint: status=%d body=%s", w.Code, w.Body)
	}
	if w := f.do("POST", "/api/users/alice/challenges/01-recon/steps/0/check", "alice@ctf.local", map[string]any{"checked": true}); w.Code != http.StatusOK {
		t.Fatalf("check step: status=%d body=%s", w.Code, w.Body)
	}

	w := f.do("GET", "/api/users/alice/journey?mission=01-recon", "alice@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("journey: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)

	schema := spec.SchemaByName("Journey")
	if schema == nil {
		t.Fatal("spec has no components.schemas.Journey")
	}
	mismatches := apispec.CompareResponse(spec, schema, actual, "Journey")
	for _, m := range mismatches {
		t.Errorf("%s: extra=%v missing=%v", m.Path, m.Extra, m.Missing)
	}
	// Non-vacuous guard: this fixture must actually have produced a
	// non-empty missions[] and a non-nil detail so the array/nested
	// recursion branches of CompareResponse were exercised, not skipped.
	missions, _ := actual["missions"].([]any)
	if len(missions) == 0 {
		t.Fatal("fixture produced an empty missions[] — the array-recursion branch of V5 was never exercised")
	}
	detail, _ := actual["detail"].(map[string]any)
	if detail == nil {
		t.Fatal("fixture produced a nil detail — the nested-object branch of V5 was never exercised")
	}
	steps, _ := detail["steps"].([]any)
	if len(steps) == 0 {
		t.Fatal("fixture produced an empty detail.steps[] — steps[] was never exercised")
	}
	hints, _ := detail["hints"].(map[string]any)
	opened, _ := hints["opened"].([]any)
	if len(opened) == 0 {
		t.Fatal("fixture produced an empty detail.hints.opened[] — OpenedHint was never exercised")
	}
}

func TestAPISpec_V5_MeFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	f.falcoFire("Recon Rule", "bob") // give bob a solve + a recent rule fire

	w := f.do("GET", "/api/users/bob/me", "bob@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("me: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("Me")
	if schema == nil {
		t.Fatal("spec has no components.schemas.Me")
	}
	for _, m := range apispec.CompareResponse(spec, schema, actual, "Me") {
		t.Errorf("%s: extra=%v missing=%v", m.Path, m.Extra, m.Missing)
	}
	if solved, _ := actual["solved"].([]any); len(solved) == 0 {
		t.Fatal("fixture produced an empty solved[] — SolveEntry was never exercised")
	}
}

func TestAPISpec_V5_StateFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	f.falcoFire("Recon Rule", "carol")
	f.submit("02-evade", "carol", "FALCO{ok}")

	w := f.do("GET", "/api/state", specFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("state: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("State")
	if schema == nil {
		t.Fatal("spec has no components.schemas.State")
	}
	for _, m := range apispec.CompareResponse(spec, schema, actual, "State") {
		t.Errorf("%s: extra=%v missing=%v", m.Path, m.Extra, m.Missing)
	}
	leaderboard, _ := actual["leaderboard"].([]any)
	if len(leaderboard) == 0 {
		t.Fatal("fixture produced an empty leaderboard[] — LeaderboardEntry was never exercised")
	}
	challenges, _ := actual["challenges"].([]any)
	if len(challenges) == 0 {
		t.Fatal("fixture produced an empty challenges[] — ChallengeStat was never exercised")
	}
	recent, _ := actual["recent_solves"].([]any)
	if len(recent) == 0 {
		t.Fatal("fixture produced an empty recent_solves[] — SolveRecord was never exercised")
	}
}

// TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec is V5 applied to a
// VARIANT-shaped success schema: SubmitFlagVerdict declares only `correct`
// as required, and its four documented outcomes (wrong flag / forbidden
// fired / exfil required / solved) each surface a different subset of the
// seven declared properties (api.go's submit handler — see its switch over
// scoring.Evade*). No SINGLE call can ever satisfy a literal "actual keys ==
// spec properties" comparison for this schema, so this test interprets
// ADR-0005 V5's "exact match" at the aggregate level: the UNION of keys
// observed across all four documented branches must equal the schema's
// declared properties (no key the schema promises is unreachable by ANY
// branch, and no branch ever emits a key the schema does not declare). This
// is a JUDGMENT CALL made during implementation, not spelled out in
// ADR-0005's text — flagged as such in the PR report.
func TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	wrong := f.submit("02-evade", "dave", "FALCO{wrong}")
	if v, _ := wrong["correct"].(bool); v {
		t.Fatalf("expected wrong-flag branch, got %+v", wrong)
	}

	f.falcoFire("Recon Rule", "erin")     // solve 01-recon -> 02-evade becomes current
	f.falcoFire("Forbidden Rule", "erin") // taint 02-evade while current (ADR-0003 A1/A2)
	forbidden := f.submit("02-evade", "erin", "FALCO{ok}")
	if evaded, ok := forbidden["evaded"].(bool); !ok || evaded {
		t.Fatalf("expected forbidden-fired branch (evaded=false), got %+v", forbidden)
	}

	f.falcoFire("Recon Rule", "frank")                     // solve 01-recon -> 02-evade current
	solved02 := f.submit("02-evade", "frank", "FALCO{ok}") // no dirty -> solves, unlocking 03-boss
	if solved, _ := solved02["solved"].(bool); !solved {
		t.Fatalf("expected frank to solve 02-evade as a precondition, got %+v", solved02)
	}
	exfilRequired := f.submit("03-boss", "frank", "FALCO{boss}")
	if exfiltrated, ok := exfilRequired["exfiltrated"].(bool); !ok || exfiltrated {
		t.Fatalf("expected exfil-required branch (exfiltrated=false), got %+v", exfilRequired)
	}

	f.falcoFire("Recon Rule", "grace")
	solved := f.submit("02-evade", "grace", "FALCO{ok}")
	if v, _ := solved["solved"].(bool); !v {
		t.Fatalf("expected solved branch, got %+v", solved)
	}

	schema := spec.SchemaByName("SubmitFlagVerdict")
	if schema == nil {
		t.Fatal("spec has no components.schemas.SubmitFlagVerdict")
	}
	want := spec.PropertyNames(schema)

	union := map[string]bool{}
	branches := []map[string]any{wrong, forbidden, exfilRequired, solved}
	for _, b := range branches {
		for k := range b {
			union[k] = true
			if !want[k] {
				t.Errorf("branch %+v has key %q not declared in SubmitFlagVerdict.properties", b, k)
			}
		}
	}
	for k := range want {
		if !union[k] {
			t.Errorf("SubmitFlagVerdict.properties declares %q but no documented branch ever emitted it", k)
		}
	}
}

// --- V8 (real spec + real table mutation proof) --------------------------

// TestAPISpec_V8_MutationsFailAgainstRealData re-runs the three ADR-0005 V8
// mutation classes — route removed, origin-guard flag flipped, response
// field renamed — against TODAY's real docs/openapi-scoreboard.yaml and
// today's real Routes()/Journey response, not the synthetic fixtures in
// internal/apispec/parity_test.go. A passing result here means the parity
// checks would actually catch a real regression in this exact codebase,
// not just in the abstract.
func TestAPISpec_V8_MutationsFailAgainstRealData(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	routes := f.srv.Routes()
	specOps := spec.Operations()

	t.Run("route_removed", func(t *testing.T) {
		mutated := make([]apispec.Route, 0, len(routes)-1)
		for _, rt := range routes {
			if rt.MuxPattern() == "GET /api/state" {
				continue // drop it, simulating a Register that forgot this route
			}
			mutated = append(mutated, rt)
		}
		specOnly, _ := apispec.RouteSetDiff(specOps, mutated)
		if len(specOnly) != 1 || specOnly[0] != "GET /api/state" {
			t.Fatalf("expected the removed route to be flagged as specOnly=[GET /api/state], got %v", specOnly)
		}
	})

	t.Run("origin_guard_flipped", func(t *testing.T) {
		mutated := append([]apispec.Route(nil), routes...)
		flippedAny := false
		for i := range mutated {
			if mutated[i].MuxPattern() == "POST /api/admin/reset" {
				mutated[i].OriginGuarded = false // real value is true (Decision 4)
				flippedAny = true
			}
		}
		if !flippedAny {
			t.Fatal("test bug: POST /api/admin/reset not found in the real route table")
		}
		_, _, onlySpec := apispec.BoolExtParity(specOps, mutated, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
		found := false
		for _, k := range onlySpec {
			if k == "POST /api/admin/reset" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected onlySpec to flag POST /api/admin/reset, got %v", onlySpec)
		}
	})

	t.Run("field_renamed", func(t *testing.T) {
		w := f.do("GET", "/api/users/hank/me", "hank@ctf.local", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("me: status=%d body=%s", w.Code, w.Body)
		}
		actual := f.decodedJSON(w)
		actual["points"] = actual["score"] // simulate a handler rename that forgot the spec
		delete(actual, "score")

		schema := spec.SchemaByName("Me")
		mismatches := apispec.CompareResponse(spec, schema, actual, "Me")
		if len(mismatches) != 1 {
			t.Fatalf("expected exactly one mismatch, got %d: %+v", len(mismatches), mismatches)
		}
		m := mismatches[0]
		if len(m.Extra) != 1 || m.Extra[0] != "points" || len(m.Missing) != 1 || m.Missing[0] != "score" {
			t.Fatalf("expected extra=[points] missing=[score], got extra=%v missing=%v", m.Extra, m.Missing)
		}
	})
}
