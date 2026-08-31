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
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/qa"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

func loadScoreboardSpec(t *testing.T) *specparity.Spec {
	t.Helper()
	spec, err := specparity.LoadSpec(filepath.Join("..", "..", "docs", "openapi-scoreboard.yaml"))
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
		// 04-proof (ADR-0008): not in WithOrder below (free-browsing only, never
		// "current" for any test user) — exists solely so
		// TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec can exercise the
		// EvadeExpectedRuleFireRequired branch and its `proven` response key.
		"04-proof": {
			ID: "04-proof", Type: "evade", ExpectedRules: []string{"Proof Rule"},
			ExpectedFlag: "FALCO{proof}", RequireExpectedRuleFire: true,
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
	qaSt, err := qa.Open(filepath.Join(t.TempDir(), "apispec-qa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { qaSt.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithJourneys(journeys),
		scoreboard.WithOrder([]string{"01-recon", "02-evade", "03-boss"}),
		scoreboard.WithAdminEmails([]string{specFixtureAdmin}),
		scoreboard.WithAllowedOrigins([]string{specFixtureOrigin}),
		scoreboard.WithQA(qaSt),
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

	specOnly, implOnly := specparity.RouteSetDiff(specOps, routes)
	if len(specOnly) > 0 {
		t.Errorf("documented but not implemented: %v", specOnly)
	}
	if len(implOnly) > 0 {
		t.Errorf("implemented but undocumented: %v", implOnly)
	}
	// Pinning the known-good count is NOT about a same-size swap defeating
	// RouteSetDiff — a route removed + a different one added would still
	// show up as one specOnly + one implOnly entry there; set diff is exact
	// CONTENT comparison, it cannot "cancel out" (LOW, 5x review: an earlier
	// version of this comment claimed otherwise, which is not a real
	// detection gap and isn't why this assert exists). The actual value is
	// PROCESS, not detection: this literal `27` forces every PR that adds or
	// removes a route to touch this line, so the route-count CHANGE itself
	// shows up in the diff and gets reviewed, instead of silently sliding
	// through as "RouteSetDiff was still empty, so nothing to see here" —
	// matches ADR-0005 C1's real-world count (20) plus ADR-0006's P25 QA
	// ticket-chat routes (7) plus app#116's /static/tokens.css route (1),
	// minus app#84's removal of the orphaned operator-broadcast hint API
	// (GET /api/hints, POST /api/admin/hints — P22-1 follow-up, dead code
	// once the docs-site hint timer it served was retired), plus Issue #95's
	// POST /csp-report (CSP violation report intake).
	if len(routes) != 27 {
		t.Errorf("expected 27 registered routes (ADR-0005 C1 + ADR-0006 P25 + app#116 - app#84 + app#95), got %d: %v", len(routes), routes)
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

	missingKey, onlyImpl, onlySpec := specparity.BoolExtParity(specOps, routes, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
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
	// ADR-0005 Decision 4's documented current-truth count. Requirement 6.4
	// (final review round): shares wantOriginGuardedRouteCount with
	// origin_guard_test.go's own count assert instead of duplicating the
	// literal `7` in a second file (same package — scoreboard_test — so the
	// constant is visible here with no import).
	if len(guarded) != wantOriginGuardedRouteCount {
		t.Errorf("expected %d origin-guarded routes (ADR-0005 Decision 4), got %d: %v", wantOriginGuardedRouteCount, len(guarded), guarded)
	}

	missingKey, onlyImpl, onlySpec = specparity.BoolExtParity(specOps, routes, "x-ctf-collector-forward", func(rt apispec.Route) bool { return rt.CollectorForward })
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

// TestAPISpec_V3b_StringExtParity is HIGH 4 (5x review): x-ctf-audience /
// x-ctf-authz / x-ctf-rate-limit were declared mandatory (ADR-0005 Decision
// 2(b)) but had zero real value-comparison coverage — R2/R3 independently
// demonstrated that reversing GET /api/hints' x-ctf-authz from "none" to
// "admin" in docs/openapi-scoreboard.yaml (a false "this needs admin"
// declaration on an intentionally-unauthenticated route — the exact
// "documented but a lie" shape ADR-0005 calls out as worst) passed `make
// test` unchanged, because apispec.StringExt had no caller anywhere. This
// wires specparity.StringExtParity in for real, against the actual spec and
// route table. (GET /api/hints itself was removed as dead code — app#84 —
// but the mutation-detection proof below still needs SOME AuthzNone route,
// so it now targets GET /healthz.)
func TestAPISpec_V3b_StringExtParity(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	routes := f.srv.Routes()
	specOps := spec.Operations()

	cases := []struct {
		key   string
		value func(apispec.Route) string
	}{
		{"x-ctf-audience", func(rt apispec.Route) string { return string(rt.Audience) }},
		{"x-ctf-authz", func(rt apispec.Route) string { return string(rt.Authz) }},
		{"x-ctf-rate-limit", func(rt apispec.Route) string { return rt.RateLimit }},
	}
	for _, c := range cases {
		missingKey, mismatched := specparity.StringExtParity(specOps, routes, c.key, c.value)
		if len(missingKey) > 0 {
			t.Errorf("%s: missing on spec operations: %v", c.key, missingKey)
		}
		if len(mismatched) > 0 {
			t.Errorf("%s parity failed: %v", c.key, mismatched)
		}
	}
}

// --- V4's dedicated ADR-0003 A2-2 assert (scoreboard side) --------------

func TestAPISpec_V4_ResetDirtyNeverForwarded(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	specOps := spec.Operations()
	routes := f.srv.Routes()

	if got := specparity.ResetDirtySpecViolation(specOps); got != "" {
		t.Error(got)
	}
	if got := specparity.ResetDirtyRouteViolation(routes); got != "" {
		t.Error(got)
	}
	// Requirement 6.2 (final review round): the origin-guard half of
	// reset-dirty's contract, named — not just implied by
	// origin_guard_test.go's `guarded != wantOriginGuardedRouteCount` count.
	if got := specparity.ResetDirtyOriginGuardViolation(routes); got != "" {
		t.Error(got)
	}
	// Sanity: the route must actually exist and be reachable at the pattern
	// this check hardcodes — otherwise both violations above would be
	// vacuously "" because ResetDirtyPattern never matched anything.
	found := false
	for _, rt := range routes {
		if rt.MuxPattern() == specparity.ResetDirtyPattern {
			found = true
		}
	}
	if !found {
		t.Fatalf("specparity.ResetDirtyPattern %q matched no registered route — the dedicated A2-2 assert is vacuous", specparity.ResetDirtyPattern)
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
	mismatches := specparity.CompareResponse(spec, schema, actual, "Journey")
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
	for _, m := range specparity.CompareResponse(spec, schema, actual, "Me") {
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
	for _, m := range specparity.CompareResponse(spec, schema, actual, "State") {
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
// as required, and its five documented outcomes (wrong flag / forbidden
// fired / proof required (ADR-0008) / exfil required / solved) each surface
// a different subset of the eight declared properties (api.go's submit
// handler — see its switch over scoring.Evade*). No SINGLE call can ever
// satisfy a literal "actual keys == spec properties" comparison for this
// schema, so this test interprets ADR-0005 V5's "exact match" at the
// aggregate level: the UNION of keys
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

	// ADR-0008: 04-proof requires a positive expectedRules fire that "heidi"
	// has never produced — evaluateClean's gate 5 (expectedRuleFire) rejects
	// before ever reaching the (absent, for this mission) exfil gate.
	proofRequired := f.submit("04-proof", "heidi", "FALCO{proof}")
	if proven, ok := proofRequired["proven"].(bool); !ok || proven {
		t.Fatalf("expected proof-required branch (proven=false), got %+v", proofRequired)
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
	branches := []map[string]any{wrong, forbidden, proofRequired, exfilRequired, solved}
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

// --- ADR-0009 Decision A: machine-derived V5 coverage ---------------------

// v5Coverage is ADR-0009 Decision A point 2: every scoreboard operation
// specparity.ResponseObjectOperations() derives from docs/openapi-scoreboard.yaml,
// mapped to whether a V5 field-comparison test exists for it.
// TestAPISpec_VA1_ResponseObjectCoverageBidirectional below enforces this
// table stays EXACTLY in sync with the derivation: an entry cannot be added
// speculatively (that would be "stale coverage entry") and an operation
// cannot be added to the spec without a field test landing in the SAME PR
// (that would be "documented, no coverage") — ADR-0005 Decision 1's
// no-exclusion-list discipline, applied to response schemas instead of
// routes.
var v5Coverage = map[string]bool{
	"GET /healthz": true, // TestAPISpec_V5_HealthzFieldsMatchSpec
	// TestAPISpec_VB2_FalcoEventsOneOfBranchesMatchSpec already performs a
	// real CompareResponse field comparison against BOTH oneOf branches
	// (ADR-0009 Decision B) — that satisfies "a V5 field-comparison test
	// exists for this operation" without a second, differently-named test.
	"POST /falco/events":                                        true,
	"POST /api/challenges/{cid}/submit":                         true, // TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec
	"POST /api/challenges/{cid}/submit-detect":                  true, // TestAPISpec_V5_SubmitDetectVerdictFieldsMatchSpec
	"POST /internal/exfil/{cid}":                                true, // TestAPISpec_V5_ExfilReceiptFieldsMatchSpec
	"GET /api/users/{user}/me":                                  true, // TestAPISpec_V5_MeFieldsMatchSpec
	"GET /api/users/{user}/journey":                             true, // TestAPISpec_V5_JourneyFieldsMatchSpec
	"POST /api/users/{user}/challenges/{cid}/steps/{idx}/check": true, // TestAPISpec_V5_StepCheckResultFieldsMatchSpec
	"POST /api/users/{user}/challenges/{cid}/hints/{idx}":       true, // TestAPISpec_V5_OpenHintResultFieldsMatchSpec
	"POST /api/users/{user}/challenges/{cid}/reset-dirty":       true, // TestAPISpec_V5_ResetDirtyResultFieldsMatchSpec
	"POST /api/users/{user}/display-name":                       true, // TestAPISpec_V5_DisplayNameResultFieldsMatchSpec
	"GET /api/users/{user}/questions":                           true, // TestAPISpec_V5_QuestionListFieldsMatchSpec
	"POST /api/users/{user}/questions":                          true, // TestAPISpec_V5_QuestionThreadFieldsMatchSpec (create branch)
	"GET /api/users/{user}/questions/{qid}":                     true, // TestAPISpec_V5_QuestionThreadFieldsMatchSpec (get branch)
	"POST /api/users/{user}/questions/{qid}/messages":           true, // TestAPISpec_V5_QuestionThreadFieldsMatchSpec (message branch)
	"GET /api/state":                                            true, // TestAPISpec_V5_StateFieldsMatchSpec
	"POST /api/admin/reset":                                     true, // TestAPISpec_V5_AdminResetResultFieldsMatchSpec
	"POST /api/admin/users/{user}/display-name":                 true, // TestAPISpec_V5_AdminDisplayNameResultFieldsMatchSpec
	"GET /api/admin/questions":                                  true, // TestAPISpec_V5_AdminQuestionListFieldsMatchSpec
	"GET /api/admin/questions/{qid}":                            true, // TestAPISpec_V5_AdminQuestionThreadFieldsMatchSpec (get branch)
	"POST /api/admin/questions/{qid}/reply":                     true, // TestAPISpec_V5_AdminQuestionThreadFieldsMatchSpec (reply branch)
}

// TestAPISpec_VA1_ResponseObjectCoverageBidirectional is ADR-0009
// Verification V(A)-1's core check against the REAL spec + REAL v5Coverage
// table (RouteSetDiff's V1 shape, applied to specparity.ResponseObjectOperations()
// vs. v5Coverage instead of a route table).
func TestAPISpec_VA1_ResponseObjectCoverageBidirectional(t *testing.T) {
	spec := loadScoreboardSpec(t)
	derived := specparity.ResponseObjectOperations(spec)

	// ADR-0009 V(A)-2: a silently-empty derivation must not read as "no diff".
	if len(derived) == 0 {
		t.Fatal("specparity.ResponseObjectOperations() returned zero operations for docs/openapi-scoreboard.yaml — derivation is broken, not clean")
	}

	derivedOnly, coverageOnly := specparity.CoverageDiff(derived, v5Coverage)
	if len(derivedOnly) > 0 {
		t.Errorf("documented operation(s) with NO V5 field-comparison test: %v", derivedOnly)
	}
	if len(coverageOnly) > 0 {
		t.Errorf("stale v5Coverage entr(y/ies) (operation no longer derived from the spec): %v", coverageOnly)
	}

	// ADR-0009 C2's 14 (scoreboard) + Decision A point 4's 7 QuestionList/
	// QuestionThread additions = 21. Same PROCESS reasoning as V1's route
	// count pin above: forces every PR that adds/removes a response-object
	// operation to touch this line, so the count change itself gets
	// reviewed instead of silently passing because the bidirectional diff
	// above happened to stay empty.
	if len(derived) != 21 {
		t.Errorf("expected 21 response-object operations (ADR-0009 C2 + Decision A), got %d: %v", len(derived), derived)
	}
}

// TestAPISpec_VA1_MutationsFailBothDirections is ADR-0009 Verification
// V(A)-1's explicit mutation-testing requirement: BOTH directions of
// CoverageDiff must go red against TODAY's real derived set, not just in the
// abstract (internal/apispec/specparity/parity_test.go already proves the
// algorithm itself against synthetic fixtures — this re-runs it against the
// real docs/openapi-scoreboard.yaml, mirroring how TestAPISpec_V8_* re-runs
// the V8 mutation classes for real).
func TestAPISpec_VA1_MutationsFailBothDirections(t *testing.T) {
	spec := loadScoreboardSpec(t)
	derived := specparity.ResponseObjectOperations(spec)

	t.Run("derived_only_documented_no_coverage", func(t *testing.T) {
		mutated := make(map[string]bool, len(v5Coverage))
		for k, v := range v5Coverage {
			mutated[k] = v
		}
		delete(mutated, "GET /healthz") // simulate: the field test for this operation was never written
		derivedOnly, _ := specparity.CoverageDiff(derived, mutated)
		found := false
		for _, k := range derivedOnly {
			if k == "GET /healthz" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected derivedOnly to flag GET /healthz, got %v", derivedOnly)
		}
	})

	t.Run("coverage_only_stale_entry", func(t *testing.T) {
		mutated := make(map[string]bool, len(v5Coverage)+1)
		for k, v := range v5Coverage {
			mutated[k] = v
		}
		mutated["GET /api/does-not-exist"] = true // simulate: a table entry left behind after a route removal
		_, coverageOnly := specparity.CoverageDiff(derived, mutated)
		found := false
		for _, k := range coverageOnly {
			if k == "GET /api/does-not-exist" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected coverageOnly to flag GET /api/does-not-exist, got %v", coverageOnly)
		}
	})
}

// --- ADR-0009 Decision A: the newly-required V5 field-comparison tests ---
//
// One test per operation ResponseObjectOperations() derives that the pre-
// existing 4 V5 tests (+ VB2's oneOf test) did not already cover. Each
// follows the SAME shape as the existing V5 tests above: build a real
// request through the shared fixture, decode the JSON body, and assert
// CompareResponse returns zero mismatches against the spec's declared
// schema.

func TestAPISpec_V5_HealthzFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	w := f.do("GET", "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("Health")
	if schema == nil {
		t.Fatal("spec has no components.schemas.Health")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "Health") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_ExfilReceiptFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t) // "03-boss" has RequireExfil: true

	w := f.do("POST", "/internal/exfil/03-boss", "", map[string]any{"user": "mona", "flag": "FALCO{boss}"})
	if w.Code != http.StatusOK {
		t.Fatalf("exfil: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("ExfilReceipt")
	if schema == nil {
		t.Fatal("spec has no components.schemas.ExfilReceipt")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "ExfilReceipt") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_StepCheckResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t) // "01-recon" has journey content (2 steps)

	w := f.do("POST", "/api/users/nina/challenges/01-recon/steps/0/check", "nina@ctf.local", map[string]any{"checked": true})
	if w.Code != http.StatusOK {
		t.Fatalf("step check: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("StepCheckResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.StepCheckResult")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "StepCheckResult") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_OpenHintResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t) // "01-recon" has journey content (2 hints)

	w := f.do("POST", "/api/users/oscar/challenges/01-recon/hints/1", "oscar@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("open hint: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("OpenHintResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.OpenHintResult")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "OpenHintResult") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_ResetDirtyResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	// Idempotent no-op reset (paul was never tainted) — ResetDirtyResult's
	// shape does not vary with whether the pair was actually dirty.
	w := f.do("POST", "/api/users/paul/challenges/02-evade/reset-dirty", "paul@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-dirty: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("ResetDirtyResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.ResetDirtyResult")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "ResetDirtyResult") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_DisplayNameResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	// No X-Auth-Request-Email header: this participant route's ONLY real
	// caller is the collector's verbatim forward of a workspace curl
	// (claimed-identity fallback — see the spec operation's own
	// description), so this is the realistic caller shape to test.
	w := f.do("POST", "/api/users/quinn/display-name", "", map[string]any{"name": "Quinn"})
	if w.Code != http.StatusOK {
		t.Fatalf("display-name: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("DisplayNameResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.DisplayNameResult")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "DisplayNameResult") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_AdminResetResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	w := f.do("POST", "/api/admin/reset", specFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reset: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("AdminResetResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.AdminResetResult")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "AdminResetResult") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

func TestAPISpec_V5_AdminDisplayNameResultFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	w := f.do("POST", "/api/admin/users/rick/display-name", specFixtureAdmin, map[string]any{"name": "Rick"})
	if w.Code != http.StatusOK {
		t.Fatalf("admin display-name: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("DisplayNameResult")
	if schema == nil {
		t.Fatal("spec has no components.schemas.DisplayNameResult")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "DisplayNameResult") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
}

// TestAPISpec_V5_QuestionListFieldsMatchSpec covers the PARTICIPANT listing
// (GET /api/users/{user}/questions). Deliberately exercised with ZERO
// tickets: docs/openapi-scoreboard.yaml's QuestionSummary.user is declared
// as a `properties` entry but is NOT in `required`, and
// qa.Store.ListForUser never sets it (see the schema's own description,
// "only present in the ADMIN listing" — internal/scoreboard/api/qa_oapi.go's
// toOapiSummary carries it through as a nil *string, so it is genuinely
// ABSENT from the JSON, not null). V5's exact-key-match rule compares the
// full declared `properties` set (spec.go's PropertyNames doc: deliberately
// NOT `required`, so it does not special-case this), so populating this
// list and letting CompareResponse recurse into a `user`-less
// QuestionSummary would report a "missing: [user]" mismatch — a real,
// pre-existing, INTENTIONAL schema/handler asymmetry (documented in the
// spec's own prose) that ADR-0009 Decision A/B does not touch or resolve.
// TestAPISpec_V5_AdminQuestionListFieldsMatchSpec below exercises the
// non-vacuous QuestionSummary recursion instead, where ListAll DOES always
// set `user`. See the PR report for this judgment call.
func TestAPISpec_V5_QuestionListFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	w := f.do("GET", "/api/users/sam/questions", "sam@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("questions list: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("QuestionList")
	if schema == nil {
		t.Fatal("spec has no components.schemas.QuestionList")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "QuestionList") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
	if questions, _ := actual["questions"].([]any); len(questions) != 0 {
		t.Fatalf("test bug: expected zero tickets for a fresh user, got %d", len(questions))
	}
}

// TestAPISpec_V5_QuestionThreadFieldsMatchSpec exercises all THREE
// participant operations whose 200 schema is QuestionThread — createQuestion,
// getQuestion, postQuestionMessage — since QuestionThread's shape does not
// vary by which route produced it (unlike SubmitFlagVerdict/
// SubmitDetectVerdict's branch-dependent keys, every declared property is
// always present here, so a single schema comparison per call is enough; no
// union-of-branches judgment call needed).
func TestAPISpec_V5_QuestionThreadFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	schema := spec.SchemaByName("QuestionThread")
	if schema == nil {
		t.Fatal("spec has no components.schemas.QuestionThread")
	}
	compare := func(label string, actual map[string]any) {
		t.Helper()
		for _, m := range specparity.CompareResponse(spec, schema, actual, label) {
			t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
		}
	}

	w := f.do("POST", "/api/users/tara/questions", "tara@ctf.local", map[string]any{"subject": "help", "body": "how do I start?"})
	if w.Code != http.StatusOK {
		t.Fatalf("create question: status=%d body=%s", w.Code, w.Body)
	}
	created := f.decodedJSON(w)
	compare("QuestionThread(create)", created)
	qid, _ := created["id"].(string)
	if qid == "" {
		t.Fatal("created ticket has no id — cannot exercise get/messages")
	}
	if messages, _ := created["messages"].([]any); len(messages) == 0 {
		t.Fatal("created ticket has an empty messages[] — the array-recursion branch was never exercised")
	}

	w = f.do("GET", "/api/users/tara/questions/"+qid, "tara@ctf.local", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get question: status=%d body=%s", w.Code, w.Body)
	}
	compare("QuestionThread(get)", f.decodedJSON(w))

	w = f.do("POST", "/api/users/tara/questions/"+qid+"/messages", "tara@ctf.local", map[string]any{"body": "any update?"})
	if w.Code != http.StatusOK {
		t.Fatalf("post message: status=%d body=%s", w.Code, w.Body)
	}
	compare("QuestionThread(message)", f.decodedJSON(w))
}

// TestAPISpec_V5_AdminQuestionListFieldsMatchSpec covers the ADMIN listing
// (GET /api/admin/questions) — the QuestionList/QuestionSummary companion
// to the participant test above, seeded with one ticket so ListAll's
// always-set `user` field exercises the array-recursion branch
// non-vacuously (the asymmetry TestAPISpec_V5_QuestionListFieldsMatchSpec's
// doc comment explains).
func TestAPISpec_V5_AdminQuestionListFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)

	w := f.do("POST", "/api/users/uma/questions", "uma@ctf.local", map[string]any{"subject": "s", "body": "b"})
	if w.Code != http.StatusOK {
		t.Fatalf("seed ticket: status=%d body=%s", w.Code, w.Body)
	}

	w = f.do("GET", "/api/admin/questions", specFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin questions list: status=%d body=%s", w.Code, w.Body)
	}
	actual := f.decodedJSON(w)
	schema := spec.SchemaByName("QuestionList")
	if schema == nil {
		t.Fatal("spec has no components.schemas.QuestionList")
	}
	for _, m := range specparity.CompareResponse(spec, schema, actual, "QuestionList") {
		t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
	}
	if questions, _ := actual["questions"].([]any); len(questions) == 0 {
		t.Fatal("fixture produced an empty questions[] — the array-recursion branch was never exercised")
	}
}

// TestAPISpec_V5_AdminQuestionThreadFieldsMatchSpec covers the two ADMIN
// operations whose 200 schema is QuestionThread — adminGetQuestion and
// adminReplyQuestion.
func TestAPISpec_V5_AdminQuestionThreadFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	f := newSpecFixture(t)
	schema := spec.SchemaByName("QuestionThread")
	if schema == nil {
		t.Fatal("spec has no components.schemas.QuestionThread")
	}
	compare := func(label string, actual map[string]any) {
		t.Helper()
		for _, m := range specparity.CompareResponse(spec, schema, actual, label) {
			t.Errorf("%s: extra=%v missing=%v note=%q", m.Path, m.Extra, m.Missing, m.Note)
		}
	}

	w := f.do("POST", "/api/users/vera/questions", "vera@ctf.local", map[string]any{"subject": "s", "body": "b"})
	if w.Code != http.StatusOK {
		t.Fatalf("seed ticket: status=%d body=%s", w.Code, w.Body)
	}
	qid, _ := f.decodedJSON(w)["id"].(string)
	if qid == "" {
		t.Fatal("seed ticket has no id")
	}

	w = f.do("GET", "/api/admin/questions/"+qid, specFixtureAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin get question: status=%d body=%s", w.Code, w.Body)
	}
	compare("QuestionThread(admin get)", f.decodedJSON(w))

	w = f.do("POST", "/api/admin/questions/"+qid+"/reply", specFixtureAdmin, map[string]any{"body": "here's how"})
	if w.Code != http.StatusOK {
		t.Fatalf("admin reply: status=%d body=%s", w.Code, w.Body)
	}
	replied := f.decodedJSON(w)
	compare("QuestionThread(admin reply)", replied)
	if answered, _ := replied["answered"].(bool); !answered {
		t.Fatalf("expected answered=true after an admin reply, got %+v", replied)
	}
}

// fakeDetectRunner is a scriptable scoring.DetectRunner (structurally — Go
// needs no import of the interface's package to satisfy it). Duplicated
// minimally here rather than imported from scoring_test.go, matching this
// file's existing "no cross-file test-helper dependency" convention
// (falcoFire's doc comment above states the same reasoning). Grade's return
// shape is (evasionFires, benignFires int, invalid bool, err error) —
// scoring.SubmitDetect's contract.
type fakeDetectRunner struct {
	evasionFires, benignFires int
	invalid                   bool
}

func (f *fakeDetectRunner) Grade(_ context.Context, _, _ string) (int, int, bool, error) {
	return f.evasionFires, f.benignFires, f.invalid, nil
}

// newDetectSpecFixture is a DEDICATED fixture (not the shared specFixture
// above) because submit-detect needs a "detect"-type catalog entry plus a
// wired DetectRunner — neither of which the shared fixture's
// trigger/evade-only catalog carries, and adding them there would perturb
// the V1 route-count / catalog assumptions the other V5 tests pin.
func newDetectSpecFixture(t *testing.T, runner *fakeDetectRunner) *specFixture {
	t.Helper()
	cat := catalog.Catalog{
		"05-detect": {ID: "05-detect", Type: "detect"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "apispec-detect.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithAllowedOrigins([]string{specFixtureOrigin}),
		scoreboard.WithDetect(api.DetectConfig{Runner: runner}),
	)
	return &specFixture{t: t, srv: srv}
}

// TestAPISpec_V5_SubmitDetectVerdictFieldsMatchSpec follows the SAME
// aggregate-union judgment call as
// TestAPISpec_V5_SubmitFlagVerdictFieldsMatchSpec above (that test's doc
// comment explains the reasoning in full): SubmitDetectVerdict declares
// `required: [status, solved]` plus 5 further optional properties, and no
// SINGLE branch (invalid / missed / false-positive / solved —
// api/api.go's submitDetect switch over scoring.DetectStatus) ever emits
// all of them. This compares the UNION of keys observed across all four
// documented branches against the schema's declared properties.
func TestAPISpec_V5_SubmitDetectVerdictFieldsMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	runner := &fakeDetectRunner{}
	f := newDetectSpecFixture(t, runner)

	submitDetect := func(user string) map[string]any {
		t.Helper()
		w := f.do("POST", "/api/challenges/05-detect/submit-detect", user+"@ctf.local", map[string]any{"user": user, "condition": "evt.type=open"})
		if w.Code != http.StatusOK {
			t.Fatalf("submit-detect %s: status=%d body=%s", user, w.Code, w.Body)
		}
		return f.decodedJSON(w)
	}

	runner.invalid = true
	invalid := submitDetect("iris")
	if status, _ := invalid["status"].(string); status != "invalid" {
		t.Fatalf("expected invalid branch, got %+v", invalid)
	}

	runner.invalid, runner.evasionFires, runner.benignFires = false, 0, 0
	missed := submitDetect("jack")
	if status, _ := missed["status"].(string); status != "missed" {
		t.Fatalf("expected missed branch, got %+v", missed)
	}

	runner.evasionFires, runner.benignFires = 2, 1
	falsePositive := submitDetect("kim")
	if status, _ := falsePositive["status"].(string); status != "false-positive" {
		t.Fatalf("expected false-positive branch, got %+v", falsePositive)
	}

	runner.evasionFires, runner.benignFires = 2, 0
	solved := submitDetect("liam")
	if status, _ := solved["status"].(string); status != "solved" {
		t.Fatalf("expected solved branch, got %+v", solved)
	}

	schema := spec.SchemaByName("SubmitDetectVerdict")
	if schema == nil {
		t.Fatal("spec has no components.schemas.SubmitDetectVerdict")
	}
	want := spec.PropertyNames(schema)

	union := map[string]bool{}
	branches := []map[string]any{invalid, missed, falsePositive, solved}
	for _, b := range branches {
		for k := range b {
			union[k] = true
			if !want[k] {
				t.Errorf("branch %+v has key %q not declared in SubmitDetectVerdict.properties", b, k)
			}
		}
	}
	for k := range want {
		if !union[k] {
			t.Errorf("SubmitDetectVerdict.properties declares %q but no documented branch ever emitted it", k)
		}
	}
}

// --- ADR-0009 Decision B (oneOf, real spec) -------------------------------

// TestAPISpec_VB2_FalcoEventsOneOfBranchesMatchSpec is ADR-0009 Verification
// V(B)-2, run against the REAL docs/openapi-scoreboard.yaml (not a synthetic
// fixture — internal/apispec/specparity/parity_test.go already proves the
// algorithm in isolation). `POST /falco/events`'s 200 response is
// oneOf[IngestAccepted, IngestIgnored] (docs/openapi-scoreboard.yaml:406-408)
// — before ADR-0009, CompareResponse's total lack of oneOf support meant
// resolve() returned the raw {"oneOf": [...]} node, `properties` was absent,
// and the old fail-open leaf swallowed EVERY actual, including one matching
// neither branch (confirmed by real-code inspection, ADR-0009 Context C3
// point 1). This pins both directions against today's real spec: (a) an
// actual matching neither branch must be reported, (b) an actual matching
// exactly one branch (either one) must be clean.
func TestAPISpec_VB2_FalcoEventsOneOfBranchesMatchSpec(t *testing.T) {
	spec := loadScoreboardSpec(t)
	op, ok := spec.Operations()["POST /falco/events"]
	if !ok {
		t.Fatal("spec has no POST /falco/events operation")
	}
	schema := spec.OperationResponseSchema(op, "200")
	if schema == nil {
		t.Fatal("POST /falco/events 200 has no application/json schema")
	}

	// (a) actual matches neither IngestAccepted nor IngestIgnored.
	neither := map[string]any{"totally_wrong_key": true}
	if mismatches := specparity.CompareResponse(spec, schema, neither, "root"); len(mismatches) == 0 {
		t.Fatal("expected a non-empty mismatch for an actual matching no oneOf branch, got none")
	}

	// (b) actual matches exactly the IngestAccepted branch.
	accepted := map[string]any{"accepted": true, "user": "u1", "rule": "Recon Rule"}
	if mismatches := specparity.CompareResponse(spec, schema, accepted, "root"); len(mismatches) != 0 {
		t.Fatalf("expected no mismatch for a valid IngestAccepted actual, got %+v", mismatches)
	}

	// (b, other branch) actual matches exactly the IngestIgnored branch.
	ignored := map[string]any{"ignored": true, "reason": "not a ctf workspace event"}
	if mismatches := specparity.CompareResponse(spec, schema, ignored, "root"); len(mismatches) != 0 {
		t.Fatalf("expected no mismatch for a valid IngestIgnored actual, got %+v", mismatches)
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
		specOnly, _ := specparity.RouteSetDiff(specOps, mutated)
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
		_, _, onlySpec := specparity.BoolExtParity(specOps, mutated, "x-ctf-origin-guard", func(rt apispec.Route) bool { return rt.OriginGuarded })
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

	// HIGH 4 (5x review), reproduced against the real spec + real route
	// table: reversing an AuthzNone route's x-ctf-authz from "none" to
	// "admin" — a false "this needs admin" declaration on a deliberately
	// unauthenticated route — WITHOUT touching Route.Authz must be caught.
	// Originally targeted GET /api/hints; that route was removed as dead
	// code (app#84, P22-1 follow-up), so this now targets GET /healthz —
	// any AuthzNone route proves the same detection path.
	t.Run("authz_reversed_in_spec", func(t *testing.T) {
		mutatedOps := map[string]map[string]any{}
		for k, v := range specOps {
			cp := map[string]any{}
			for kk, vv := range v {
				cp[kk] = vv
			}
			mutatedOps[k] = cp
		}
		mutatedOps["GET /healthz"]["x-ctf-authz"] = "admin" // real Route.Authz stays "none"
		_, mismatched := specparity.StringExtParity(mutatedOps, routes, "x-ctf-authz", func(rt apispec.Route) string { return string(rt.Authz) })
		found := false
		for _, m := range mismatched {
			if m == `GET /healthz: impl="none" spec="admin"` {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a mismatch entry for GET /healthz, got %v", mismatched)
		}
	})

	t.Run("reset_dirty_origin_guard_flipped", func(t *testing.T) {
		// Requirement 6.2's own V8 proof: flip reset-dirty's OriginGuarded to
		// false (simulating the exact mutation app#124 5x review R1 finding
		// C3 warns against) and confirm ResetDirtyOriginGuardViolation names
		// it, rather than relying solely on origin_guard_test.go's numeric
		// `guarded != wantOriginGuardedRouteCount` assert to notice.
		mutated := append([]apispec.Route(nil), routes...)
		flippedAny := false
		for i := range mutated {
			if mutated[i].MuxPattern() == specparity.ResetDirtyPattern {
				mutated[i].OriginGuarded = false // real value is true (ADR-0003 A2-2 / app#124 5x R1 C3).
				flippedAny = true
			}
		}
		if !flippedAny {
			t.Fatal("test bug: reset-dirty's route not found in the real route table")
		}
		got := specparity.ResetDirtyOriginGuardViolation(mutated)
		if got == "" {
			t.Fatal("expected ResetDirtyOriginGuardViolation to flag the flipped OriginGuarded, got no violation")
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
		mismatches := specparity.CompareResponse(spec, schema, actual, "Me")
		if len(mismatches) != 1 {
			t.Fatalf("expected exactly one mismatch, got %d: %+v", len(mismatches), mismatches)
		}
		m := mismatches[0]
		if len(m.Extra) != 1 || m.Extra[0] != "points" || len(m.Missing) != 1 || m.Missing[0] != "score" {
			t.Fatalf("expected extra=[points] missing=[score], got extra=%v missing=%v", m.Extra, m.Missing)
		}
	})
}
