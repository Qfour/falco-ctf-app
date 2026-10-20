package authpolicy_test

import (
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
)

// TestAPISpec_RouteLabelIsClosed runs specparity.RouteLabelViolations on auth-policy's
// live Routes(): the `route` label of a request-duration histogram is the matched
// pattern, a closed set unless a CONNECT-matching subtree pattern is declared
// (app#491). The property is defined once in specparity; this entry point is
// required in every mux-owning package by parity_coverage_test.go.
func TestAPISpec_RouteLabelIsClosed(t *testing.T) {
	routes := newHandler("http://oauth2-proxy.invalid").Routes()
	if len(routes) == 0 {
		t.Fatal("auth-policy Routes() returned zero routes — the scan is empty, not clean")
	}
	for _, v := range specparity.RouteLabelViolations(routes) {
		t.Error(v)
	}
}
