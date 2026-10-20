package collector

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
)

// TestAPISpec_RouteLabelIsClosed runs specparity.RouteLabelViolations on collector's
// live Routes(): the `route` label of a request-duration histogram is the matched
// pattern, a closed set unless a CONNECT-matching subtree pattern is declared
// (app#491). The property is defined once in specparity; this entry point is
// required in every mux-owning package by parity_coverage_test.go.
func TestAPISpec_RouteLabelIsClosed(t *testing.T) {
	h := newParityFixtureHandler(t)
	routes := h.Routes()
	if len(routes) == 0 {
		t.Fatal("collector Routes() returned zero routes — the scan is empty, not clean")
	}
	for _, v := range specparity.RouteLabelViolations(routes) {
		t.Error(v)
	}
}
