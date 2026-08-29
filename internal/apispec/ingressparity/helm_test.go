package ingressparity

import (
	"os/exec"
	"testing"
)

// requireHelm skips the test with a clear reason when `helm` isn't on PATH
// (e.g. a local `go test ./...` run outside Dockerfile.test's container,
// where ADR-0021's `go install helm.sh/helm/v3/cmd/helm@...` step hasn't
// run) rather than failing opaquely inside exec.Command.
func requireHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH — this test needs it (see Dockerfile.test's `go install helm.sh/helm/v3/cmd/helm@...` step, ADR-0021 O1); skipping outside that container")
	}
}

// TestLoadIngressEntries_NonEmptyWithExplicitJourneyHost is half of
// ADR-0021 V(I15)-4's non-empty assert: with a non-empty journeyHost
// explicitly set, `helm template` on the REAL charts/scoreboard chart must
// render at least one path entry. A regression here (e.g. the chart's `if`
// guard changing shape, or this function's --set flags drifting from the
// chart's actual value name) would otherwise silently make every V(I15)-1/
// V(I15)-2 check in internal/scoreboard's ADR-0021 test vacuously pass —
// there would be nothing to compare against.
func TestLoadIngressEntries_NonEmptyWithExplicitJourneyHost(t *testing.T) {
	requireHelm(t)
	entries, err := LoadIngressEntries("app.example.invalid")
	if err != nil {
		t.Fatalf("LoadIngressEntries: %v (did `helm dependency build charts/scoreboard` run first? Dockerfile.test's RUN step does this; a local run needs it done manually)", err)
	}
	if len(entries) == 0 {
		t.Fatal("LoadIngressEntries(\"app.example.invalid\") returned 0 entries — charts/scoreboard/templates/ingress-journey.yaml rendered nothing even with a non-empty journeyHost; extraction itself is broken, not just \"no diff\"")
	}
}

// TestLoadIngressEntries_EmptyJourneyHostRendersNothing documents and
// regression-guards ADR-0021 C4's "journeyHost 空出力の罠": the chart's
// `{{- if and .Values.ingress.enabled .Values.ingress.journeyHost }}` guard
// treats journeyHost=="" (the chart's own default) as falsy, so the guarded
// template body renders to nothing — and, measured directly (not assumed),
// `helm template --show-only templates/ingress-journey.yaml` then ERRORS
// ("could not find template ... in chart") rather than succeeding with an
// empty document. This is a STRONGER fail-closed outcome than C4's prose
// anticipated ("paths 0 件 = 未カバーなしに誤読される") — a caller who
// forgets a real journeyHost gets a hard error from THIS call, not a
// silent, vacuously-green empty result. This test pins that
// LoadIngressEntries propagates the error rather than papering over it
// (e.g. by treating a "not found" helm error as "0 entries").
func TestLoadIngressEntries_EmptyJourneyHostRendersNothing(t *testing.T) {
	requireHelm(t)
	entries, err := LoadIngressEntries("")
	if err == nil {
		t.Fatalf("LoadIngressEntries(\"\") = %v entries, nil error — want an error (chart's ingress.journeyHost guard should have made `--show-only templates/ingress-journey.yaml` fail to find any rendered content); either the chart guard changed shape or this package's understanding of it (ADR-0021 C4) is stale", entries)
	}
}

// TestParseIngressEntries_MultiDocumentFailsClosed is review-5x R2-F4's (LOW)
// regression guard: parseIngressEntries must FAIL (not silently keep only
// the first document's entries) when its input contains more than one
// "---"-separated YAML document — the failure mode a plain single-shot
// yaml.Unmarshal would have had, and the one this package's whole design
// (D4, ADR-0021 C4 — extraction must never quietly drop data) exists to
// avoid. No `helm` binary needed — this feeds synthetic YAML bytes directly.
func TestParseIngressEntries_MultiDocumentFailsClosed(t *testing.T) {
	const twoDocuments = `apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
    - host: a.example.invalid
      http:
        paths:
          - path: /portal
            pathType: Exact
---
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
    - host: b.example.invalid
      http:
        paths:
          - path: /api/users/
            pathType: Prefix
`
	entries, err := parseIngressEntries([]byte(twoDocuments))
	if err == nil {
		t.Fatalf("parseIngressEntries(2 documents) = %v entries, nil error — want an error; a second document's paths[] entries (here /api/users/) must never be silently dropped", entries)
	}
}

// TestParseIngressEntries_SingleDocumentStillWorks is the non-mutated
// control for the guard above: a single document must still decode
// normally, so the multi-document check can't pass its own test above
// vacuously by rejecting everything.
func TestParseIngressEntries_SingleDocumentStillWorks(t *testing.T) {
	const oneDocument = `apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
    - host: a.example.invalid
      http:
        paths:
          - path: /portal
            pathType: Exact
`
	entries, err := parseIngressEntries([]byte(oneDocument))
	if err != nil {
		t.Fatalf("parseIngressEntries(1 document): unexpected error: %v", err)
	}
	want := []IngressEntry{{Path: "/portal", PathType: "Exact"}}
	if len(entries) != 1 || entries[0] != want[0] {
		t.Errorf("parseIngressEntries(1 document) = %v, want %v", entries, want)
	}
}
