package scoreboard_test

// ADR-0021 (Issue #238) — Hard Invariant I15: the scoreboard's single-origin
// production ingress (charts/scoreboard/templates/ingress-journey.yaml)
// must let EVERY apispec.AudienceParticipant mux Route through, and must
// NOT let any other-audience route through via a Prefix entry. This is a
// THIRD artifact ADR-0005's I14 (mux vs. docs/openapi-scoreboard.yaml) is
// structurally blind to — #95 (POST /csp-report) and #235
// (/vendor/cybercore.min.css, /static/tokens.css — landed in PRODUCTION)
// were both mux-declared-and-spec-declared routes missing from this
// allow-list. See docs/adr/0021-ingress-participant-route-coverage-gate.md
// for the full Context/Decision/Verification.
//
// The comparison logic itself (covers/CoverageDiff/DeadExact) is generic
// and synthetic-input-tested in internal/apispec/ingressparity's own
// coverage_test.go (V(I15)-5 cases 2-5, D3's 4 boundary cases). This file
// is the REAL-fixture half (mirrors apispec_parity_test.go's split from
// internal/apispec/parity_test.go for I14): a real scoreboard.Handler's
// Routes() against a real `helm template` of charts/scoreboard.

import (
	"os/exec"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/apispec/ingressparity"
)

// ingressJourneyTestHost is an arbitrary non-empty journeyHost (ADR-0021
// C4/V(I15)-4 — the chart's ingress-journey.yaml body is guarded on
// `.Values.ingress.journeyHost` being truthy, and its chart default is "").
// The actual string value is irrelevant to the render (it only ends up in
// `spec.rules[].host`, which this test never reads) — "example.invalid" is
// the same placeholder-domain convention charts/scoreboard/values.yaml
// itself uses for `ingress.host`.
const ingressJourneyTestHost = "app.example.invalid"

// requireHelmForIngressJourney skips with a clear reason when `helm` isn't
// on PATH, mirroring internal/apispec/ingressparity/helm_test.go's
// requireHelm (unexported there, so duplicated here rather than exported
// purely for a test-to-test call — see that package's own doc for why it
// stays test-only).
func requireHelmForIngressJourney(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH — needs Dockerfile.test's `go install helm.sh/helm/v3/cmd/helm@...` step (ADR-0021 O1); skipping outside that container")
	}
}

// allRoutesAndIngressPaths is the shared ADR-0021 extraction step for every
// test below: the FULL real scoreboard route table (every audience — NOT
// pre-filtered to AudienceParticipant) and the real chart's rendered
// participant allow-list.
//
// review-5x R2-F1 (BLOCKING): an earlier version of this helper returned
// only the AudienceParticipant subset, and TestI15_IngressJourneyRouteCoverage
// passed THAT into ingressparity.CoverageDiff. CoverageDiff's own reverse
// loop already does `if rt.Audience == apispec.AudienceParticipant {
// continue }` to skip participant routes while scanning for foreign
// (non-participant) ones reachable through a Prefix entry — feeding it an
// ALREADY-participant-only slice made that loop's condition true for every
// remaining element, so `foreign` was STRUCTURALLY always empty: injecting
// an operator/admin route under an existing Prefix (e.g. "/api/users/")
// would never turn V(I15)-2 red, even though coverage_test.go's synthetic
// "case 3" mutation test (same CoverageDiff function, given a
// deliberately-mixed-audience slice) passed fine — the bug was entirely in
// THIS integration point, not in CoverageDiff itself. CoverageDiff's own
// contract (see its doc) is that it needs the FULL route table to do the
// reverse check at all; only the forward check only ever looks at
// AudienceParticipant elements of its input. So: hand it everything.
func allRoutesAndIngressPaths(t *testing.T) ([]apispec.Route, []ingressparity.IngressEntry) {
	t.Helper()
	requireHelmForIngressJourney(t)

	f := newSpecFixture(t)
	allRoutes := f.srv.Routes()

	// V(I15)-4, route-table half: an empty PARTICIPANT subset would make
	// the forward assertion vacuously pass (nothing to check) — the same
	// "green because broken" failure mode ADR-0021 C4 warns about for I14's
	// own V8 discipline. Checked here (not by pre-filtering the slice
	// CoverageDiff receives — see the R2-F1 note above for why that's the
	// bug this replaced) so a silent extraction failure still fails loud,
	// exactly once, before either subtest runs.
	participantCount := 0
	for _, rt := range allRoutes {
		if rt.Audience == apispec.AudienceParticipant {
			participantCount++
		}
	}
	if participantCount == 0 {
		t.Fatalf("scoreboard.Handler.Routes() contains 0 AudienceParticipant routes out of %d total — extraction is broken (or every participant route lost its audience label), not \"nothing to check\"", len(allRoutes))
	}

	entries, err := ingressparity.LoadIngressEntries(ingressJourneyTestHost)
	if err != nil {
		t.Fatalf("ingressparity.LoadIngressEntries(%q): %v (did `helm dependency build charts/scoreboard` run? Dockerfile.test's RUN step does this; a local run needs it done manually first)", ingressJourneyTestHost, err)
	}
	// V(I15)-4, ingress-render half (ADR-0021 C4's actual named risk: a
	// caller forgetting `--set ingress.journeyHost=<non-empty>` and reading
	// a resulting empty render as "no diff, all good"). Measured behaviour
	// (ingressparity/helm_test.go) is that an EMPTY journeyHost actually
	// errors rather than returning 0 entries — this assert is the
	// complementary defense-in-depth for a hypothetical helm/chart change
	// that turned that error back into a silent empty render.
	if len(entries) == 0 {
		t.Fatal("ingressparity.LoadIngressEntries returned 0 path entries for a non-empty journeyHost — charts/scoreboard/templates/ingress-journey.yaml rendered nothing; extraction is broken, not \"nothing to compare\"")
	}
	return allRoutes, entries
}

// TestI15_IngressJourneyRouteCoverage is ADR-0021's main blocking gate:
// V(I15)-1 (forward: every participant route reachable through the
// ingress) and V(I15)-2 (reverse: no Prefix entry exposes a non-participant
// route) against TODAY's real chart + real route table — this run passing
// green IS Verification V(I15)-5 case 1 (the real-chart baseline; cases
// 2-5, all synthetic-input, live in
// internal/apispec/ingressparity/coverage_test.go).
//
// CoverageDiff is given the FULL route table (allRoutes), never a
// participant-only pre-filter — see allRoutesAndIngressPaths' doc (R2-F1)
// for why a pre-filtered slice structurally disables the reverse check.
func TestI15_IngressJourneyRouteCoverage(t *testing.T) {
	allRoutes, entries := allRoutesAndIngressPaths(t)
	uncovered, foreign := ingressparity.CoverageDiff(allRoutes, entries)

	t.Run("forward: every AudienceParticipant route is reachable through the ingress allow-list", func(t *testing.T) {
		if len(uncovered) > 0 {
			t.Errorf("%d participant route(s) NOT covered by charts/scoreboard/templates/ingress-journey.yaml's allow-list (this is exactly the #95/#235 defect class — a route correctly declared in the mux table AND docs/openapi-scoreboard.yaml, missing from the single-origin ingress, 404s in production even though every other layer says it should work): %v", len(uncovered), uncovered)
		}
	})

	t.Run("reverse: no ingress entry (Prefix or Exact) exposes a non-participant route", func(t *testing.T) {
		if len(foreign) > 0 {
			t.Errorf("%d non-participant route(s) reachable through a participant allow-list entry in ingress-journey.yaml (ADR-0021 D2 — an admin/operator route accidentally added under an existing Prefix, e.g. \"/api/users/\", would leak through the single-origin ingress to any authenticated login; ADR-0022 extends this to a hand-written Exact entry literally matching one, e.g. \"/api/state\"; server-side isAdmin()/selfOrAdmin() gates remain the primary defense — see ADR-0021 D2's defense-in-depth note — but this is an architecture-drift signal that should never fire): %v", len(foreign), foreign)
		}
	})
}

// TestI15_DeadExactEntriesAdvisory is ADR-0021 V(I15)-3 (advisory, NOT
// blocking — a landing-order mismatch between "rename the mux route" and
// "update the ingress chart" PRs would otherwise make this flaky for
// hygiene, not security, reasons — D2's own rationale for why this is the
// one non-blocking half of I15).
func TestI15_DeadExactEntriesAdvisory(t *testing.T) {
	// Uses the FULL route table (not just participant routes) — a dead
	// Exact entry is dead regardless of what audience the route it used to
	// match belonged to.
	requireHelmForIngressJourney(t)
	f := newSpecFixture(t)
	entries, err := ingressparity.LoadIngressEntries(ingressJourneyTestHost)
	if err != nil {
		t.Fatalf("ingressparity.LoadIngressEntries(%q): %v", ingressJourneyTestHost, err)
	}
	if dead := ingressparity.DeadExact(f.srv.Routes(), entries); len(dead) > 0 {
		t.Logf("advisory (not blocking): %d Exact entr(y/ies) in ingress-journey.yaml have no matching mux Route — likely drift from a rename/removal that didn't update the chart: %v", len(dead), dead)
	}
}
