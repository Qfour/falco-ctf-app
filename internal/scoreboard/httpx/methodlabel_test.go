package httpx

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestMethodLabel(t *testing.T) {
	tests := []struct {
		name, route, method, want string
	}{
		{"declared POST", "POST /api/challenges/{cid}/submit", "POST", "POST"},
		{"declared GET", "GET /healthz", "GET", "GET"},
		{"HEAD is served from a GET pattern and keeps its value", "GET /healthz", "HEAD", "HEAD"},
		{"a method the route does not declare", "GET /healthz", "FOO1", "other"},
		{"POST on a GET route (405)", "GET /healthz", "POST", "other"},
		{"HEAD on a POST route", "POST /api/challenges/{cid}/submit", "HEAD", "other"},
		{"nothing matched", "", "POST", "other"},
		{"nothing matched, invented method", "", "FOO1", "other"},
		{"invalid UTF-8 never reaches a label", "", "\xff\xfe", "other"},
		{"a pattern without a method is not trusted", "/healthz", "GET", "other"},
		// CONNECT: net/http reports the request-derived path as the pattern when it
		// redirects to a trailing slash, and a path may hold a space. The declared
		// part is then a path fragment, which a request can echo as its method.
		{"a request-derived path with a space is not a method", "/a b/", "/a", "other"},
		{"a lower-case declared part is not a method", "get /x", "get", "other"},
		{"an empty declared part is not a method", " /x", "", "other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MethodLabel(tc.route, tc.method); got != tc.want {
				t.Fatalf("MethodLabel(%q, %q) = %q, want %q", tc.route, tc.method, got, tc.want)
			}
		})
	}
}

// The leaf is standard library only, so the collector (a distroless image whose
// SBOM carries only what runs) imports it without taking a dependency with it.
// (internal/apispec/dependency_boundary_test.go checks the collector's closure and
// its Dockerfile COPY; this fixes the file itself.)
func TestMethodLabelLeafImportsOnlyTheStandardLibrary(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "methodlabel.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Imports) == 0 {
		t.Fatal("the leaf imports nothing; the check would pass on nothing")
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
			t.Errorf("methodlabel.go imports %q: the leaf may import the standard library only", path)
		}
	}
}
