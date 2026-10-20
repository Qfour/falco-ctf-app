package specparity

import (
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
)

func TestRouteLabelViolations(t *testing.T) {
	tests := []struct {
		name   string
		routes []apispec.Route
		want   int // violations
	}{
		{"exact patterns", []apispec.Route{{Method: "GET", Pattern: "/healthz"}, {Method: "POST", Pattern: "/api/x/{id}"}}, 0},
		{"a GET subtree is allowed (never matches CONNECT)", []apispec.Route{{Method: "GET", Pattern: "/"}}, 0},
		{"a POST subtree is allowed", []apispec.Route{{Method: "POST", Pattern: "/files/"}}, 0},
		{"a CONNECT subtree is a violation", []apispec.Route{{Method: "CONNECT", Pattern: "/tunnel/"}}, 1},
		{"a CONNECT exact pattern is allowed", []apispec.Route{{Method: "CONNECT", Pattern: "/tunnel"}}, 0},
		{"a route with no method is a violation", []apispec.Route{{Method: "", Pattern: "/files/"}}, 1},
		{"no routes: nothing to flag", nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RouteLabelViolations(tc.routes); len(got) != tc.want {
				t.Fatalf("RouteLabelViolations = %v, want %d", got, tc.want)
			}
		})
	}
	if v := RouteLabelViolations([]apispec.Route{{Method: "", Pattern: "/files/"}}); len(v) == 1 && !strings.Contains(v[0], "no method") {
		t.Fatalf("violation text %q does not say why", v[0])
	}
}
