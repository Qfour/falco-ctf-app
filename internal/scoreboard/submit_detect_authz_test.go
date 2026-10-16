package scoreboard_test

// app#346: POST /api/challenges/{cid}/submit-detect used to run the dual-path
// write gate (self-or-admin-write), whose header-less branch was a
// claimed-identity allow for the collector's forwards. After ADR-0034 S1 the
// collector no longer forwards this route and no workspace can reach it, so
// that branch had no legitimate caller. submit-detect is now plain
// self-or-admin (identity header REQUIRED, exact canonical match per ADR-0034
// S2) and the self-or-admin-write VOCABULARY — constant, spec value, gate
// function — is deleted. This file pins both halves: the route's behaviour,
// and that the vocabulary stays gone.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// submitDetectAs issues POST /api/challenges/03-detect/submit-detect on the
// authz fixture (noop detect runner, so a request that passes the gate is a
// plain 200 "missed" verdict) with an ALLOWED Origin, body user `bodyUser`,
// and X-Auth-Request-Email: email when email != "" (no header at all
// otherwise).
func submitDetectAs(t *testing.T, srv http.Handler, bodyUser, email string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/challenges/03-detect/submit-detect",
		strings.NewReader(`{"user":"`+bodyUser+`","condition":"evt.type=execve"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", allowedOrigin)
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// The table shares ONE fixture, so it depends on (a) the per-IP submit bucket
// (burst 10 per RemoteAddr; submit-detect is limited by it) — the rows must
// stay under that budget, and a new row past it turns into a 429 — and (b)
// authz_test.go's noopDetectRunner returning a "missed" verdict, which is
// what makes a request that passes the gate a plain 200.
func TestSubmitDetect_RequiresProvenIdentity(t *testing.T) {
	srv := newAuthzFixture(t)
	for _, tc := range []struct {
		name     string
		bodyUser string
		email    string
		want     int
	}{
		// The point of app#346: an allowed Origin (forgeable by anything
		// in-cluster) with NO identity header is 403, not a claimed-identity 200.
		{"no identity header (the removed claimed-identity branch)", "alice", "", http.StatusForbidden},
		{"matching identity", "alice", "alice@ctf.local", http.StatusOK},
		{"admin grading any seat", "alice", authzAdminEmail, http.StatusOK},
		{"other seat", "alice", "bob@ctf.local", http.StatusForbidden},
		{"prefix-longer seat (alice2@ is not alice@)", "alice", "alice2@ctf.local", http.StatusForbidden},
		{"same seat, foreign domain (I8: exact, not prefix)", "alice", "alice@evil.example", http.StatusForbidden},
		{"proven identity grading as another body user", "bob", "alice@ctf.local", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := submitDetectAs(t, srv, tc.bodyUser, tc.email)
			if w.Code != tc.want {
				t.Fatalf("body user %q, X-Auth-Request-Email %q: status=%d body=%s, want %d", tc.bodyUser, tc.email, w.Code, w.Body, tc.want)
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatalf("403 body is not the {\"error\": ...} shape: %s", w.Body)
			}
		})
	}
}

// --- the vocabulary stays deleted ------------------------------------------

// The identifiers/values are assembled at run time so this file itself never
// spells them out as one literal.
var (
	removedGateIdent = "selfOrAdmin" + "Write"
	removedConstName = "AuthzSelfOrAdmin" + "Write"
	removedAuthzVal  = "self-or-admin" + "-write"
)

// goSourceViolations parses src (named file) and reports every identifier
// equal to removedGateIdent / removedConstName and every string literal equal
// to removedAuthzVal — comments are deliberately ignored (history may be
// recorded in prose; code may not use the vocabulary).
func goSourceViolations(t *testing.T, file string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == removedGateIdent || x.Name == removedConstName {
				out = append(out, file+": identifier "+x.Name)
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && strings.Contains(x.Value, removedAuthzVal) {
				out = append(out, file+": string literal "+x.Value)
			}
		}
		return true
	})
	return out
}

// TestAuthz_SelfOrAdminWriteVocabularyIsGone: 0 declarations, 0 calls, 0
// route declarations, 0 spec values — in every non-test Go file under
// internal/ and cmd/ and in every docs/openapi-*.yaml.
//
// Scope: non-test .go files and docs/openapi-*.yaml ONLY. Templates and docs
// (including comments in them) are out of scope; a human fixes those.
func TestAuthz_SelfOrAdminWriteVocabularyIsGone(t *testing.T) {
	root := filepath.Join("..", "..")
	var violations []string
	parsed := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			parsed++
			violations = append(violations, goSourceViolations(t, p, nil)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	// non-vacuous: the walk really saw the api package (an empty walk is "0 violations").
	if parsed < 20 {
		t.Fatalf("parsed only %d non-test Go files under internal/ cmd/ — the walk is broken", parsed)
	}
	specs, err := filepath.Glob(filepath.Join(root, "docs", "openapi-*.yaml"))
	if err != nil || len(specs) != 3 {
		t.Fatalf("expected 3 docs/openapi-*.yaml, got %v (err %v)", specs, err)
	}
	for _, p := range specs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), removedAuthzVal) {
			violations = append(violations, p+": mentions the removed x-ctf-authz value")
		}
	}
	if len(violations) > 0 {
		t.Fatalf("the self-or-admin-write vocabulary was reintroduced (app#346: header-less claimed-identity allow has no legitimate caller):\n  %s", strings.Join(violations, "\n  "))
	}
}

// The detector is not vacuous: a source that declares/calls the removed gate,
// or declares a route with the removed value, is flagged.
func TestAuthz_SelfOrAdminWriteVocabularyDetectorCatchesReintroduction(t *testing.T) {
	for name, src := range map[string]string{
		"gate declaration": "package p\nfunc (h *H) " + removedGateIdent + "() bool { return true }\n",
		"gate call":        "package p\nfunc f(h *H) { h." + removedGateIdent + "() }\n",
		"constant":         "package p\nvar _ = apispec." + removedConstName + "\n",
		"string value":     "package p\nvar _ = \"" + removedAuthzVal + "\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if v := goSourceViolations(t, "synthetic.go", src); len(v) == 0 {
				t.Fatalf("%s was not flagged", name)
			}
		})
	}
	if v := goSourceViolations(t, "clean.go", "package p\n// prose may mention "+removedGateIdent+" (history)\nfunc g() {}\n"); len(v) != 0 {
		t.Fatalf("a comment-only mention was flagged: %v", v)
	}
}
