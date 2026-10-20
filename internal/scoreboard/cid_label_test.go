package scoreboard_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// Metric-label hygiene for the {cid} path segment: an id that is not a catalog
// key is folded into one label value, answered with a fixed body that does not
// contain the input, and never grows the series set.

const (
	submissionsFamily = "scoreboard_api_submissions_total"
	unknownCIDBody    = `{"error":"unknown challenge"}`
)

// submissionLabelValues returns the set of challenge_id label values currently
// exposed on the submissions counter (the default registry is process-wide, so
// callers compare before/after rather than assuming an empty start).
func submissionLabelValues(t *testing.T) map[string]bool {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, mf := range fams {
		if mf.GetName() != submissionsFamily {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "challenge_id" {
					out[lp.GetValue()] = true
				}
			}
		}
	}
	return out
}

// outOfGrammarCIDs returns n distinct path segments that are long and/or use
// characters outside the id grammar (all valid in a URL path once encoded).
func outOfGrammarCIDs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		switch i % 3 {
		case 0: // far longer than the id length cap
			out = append(out, fmt.Sprintf("%04d", i)+strings.Repeat("a", 4096))
		case 1: // characters outside the grammar
			out = append(out, fmt.Sprintf("bad%%20id%%2B%d", i))
		default: // the shape of the grammar (NN-slug), only longer than it allows
			out = append(out, "00-"+strings.Repeat("a", 61)+fmt.Sprint(i))
		}
	}
	return out
}

// submissions reads one challenge_id/outcome series of the submissions counter.
func submissions(cid, outcome string) float64 {
	return testutil.ToFloat64(metrics.SubmissionsTotal.WithLabelValues(cid, outcome))
}

func assertFixedUnknownBody(t *testing.T, label string, code int, body string, cid string) {
	t.Helper()
	if code != http.StatusNotFound {
		t.Fatalf("%s: status=%d body=%.120s, want 404", label, code, body)
	}
	if strings.TrimSpace(body) != unknownCIDBody {
		t.Fatalf("%s: body=%.120s, want the fixed %s", label, body, unknownCIDBody)
	}
	// The raw segment (or any slice of it) must not be reflected.
	if raw := strings.SplitN(cid, "%", 2)[0]; len(raw) >= 3 && strings.Contains(body, raw) {
		t.Fatalf("%s: body reflects the input", label)
	}
}

// Fifty ids outside the grammar must not add a series per id: they all land on
// the single "_unknown" value, on submit and on submit-detect.
func TestSubmitUnknownCIDIsFoldedIntoOneLabelValue(t *testing.T) {
	f := newSDFixture(t)
	before := submissionLabelValues(t)
	unknownBefore := submissions("_unknown", "unknown_challenge")

	cids := outOfGrammarCIDs(50)
	for i, cid := range cids {
		// A distinct client address and identity per request keeps the rate
		// limiters out of the way so every request reaches the handler.
		user := fmt.Sprintf("user%d", i+1)
		email := user + "@ctf.local"
		for _, route := range []string{"submit", "submit-detect"} {
			b, _ := json.Marshal(map[string]any{"user": user, "flag": "FALCO{x}", "condition": "evt.type=open"})
			r := httptest.NewRequest("POST", "/api/challenges/"+cid+"/"+route, bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", sdOrigin)
			r.Header.Set("X-Auth-Request-Email", email)
			r.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
			w := httptest.NewRecorder()
			f.srv.ServeHTTP(w, r)
			assertFixedUnknownBody(t, fmt.Sprintf("%s #%d", route, i), w.Code, w.Body.String(), cid)
		}
	}

	after := submissionLabelValues(t)
	for v := range after {
		if before[v] {
			continue
		}
		if v != "_unknown" {
			t.Fatalf("a new challenge_id label value %q appeared (len %d); only \"_unknown\" may", clip(v), len(v))
		}
	}
	if got, want := submissions("_unknown", "unknown_challenge")-unknownBefore, float64(2*len(cids)); got != want {
		t.Fatalf("_unknown/unknown_challenge rose by %v, want %v (every request must reach the handler and fold)", got, want)
	}
}

// A well-formed id that is simply not in the catalog gets the same fold and the
// same fixed body as an id outside the grammar.
func TestSubmitUnknownButWellFormedCIDIsFolded(t *testing.T) {
	f := newFixture(t, nil)
	unknownBefore := submissions("_unknown", "unknown_challenge")
	w := f.do("POST", "/api/challenges/99-nope/submit", map[string]any{"user": "user1", "flag": "FALCO{x}"})
	assertFixedUnknownBody(t, "99-nope", w.Code, w.Body.String(), "99-nope")
	if submissionLabelValues(t)["99-nope"] {
		t.Fatal("an id that is not a catalog key was used as a label value")
	}
	if got := submissions("_unknown", "unknown_challenge") - unknownBefore; got != 1 {
		t.Fatalf("_unknown/unknown_challenge rose by %v, want 1", got)
	}
}

// The exfil sink answers an id outside the grammar with the fixed body too.
func TestExfilInternalUnknownCIDFixedBody(t *testing.T) {
	f := newFixture(t, nil)
	for _, cid := range outOfGrammarCIDs(6) {
		w := f.exfilReq(cid, "application/json", exfilBody, nil)
		assertFixedUnknownBody(t, "exfil", w.Code, w.Body.String(), cid)
	}
}

// A catalog key still labels its own series (the fold must not hide real ids).
func TestSubmitKnownCIDKeepsItsOwnLabel(t *testing.T) {
	f := newFixture(t, nil)
	before := submissions("02-evade", "wrong_flag")
	f.do("POST", "/api/challenges/02-evade/submit", map[string]any{"user": "user1", "flag": "FALCO{wrong}"})
	if got := submissions("02-evade", "wrong_flag") - before; got != 1 {
		t.Fatalf("02-evade/wrong_flag rose by %v, want 1 (a catalog id keeps its own label)", got)
	}
}

// A cid that is not valid UTF-8 (%ff%fe) folds into the unknown label, does not
// panic (the metrics client rejects non-UTF-8 label values), is answered with
// the fixed body, and still leaves its audit line, which carries the folded
// value rather than the input.
func TestSubmitNonUTF8CIDFoldsIntoUnknownLabelAndDoesNotPanic(t *testing.T) {
	cat := catalog.Catalog{"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"}}
	st, err := store.Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var logs bytes.Buffer
	srv := scoreboard.NewHandler(cat, st, slog.New(slog.NewTextHandler(&logs, nil)),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain))

	for _, cid := range []string{"%ff%fe", "ok%ff", "%c3%28"} {
		r := httptest.NewRequest("POST", "/api/challenges/"+cid+"/submit", strings.NewReader(`{"user":"user1","flag":"FALCO{x}"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r) // a panic here fails the test
		assertFixedUnknownBody(t, "non-UTF-8 "+cid, w.Code, w.Body.String(), cid)
	}
	for v := range submissionLabelValues(t) {
		if !isValidUTF8(v) {
			t.Fatalf("a non-UTF-8 label value was recorded: %q", v)
		}
	}
	out := logs.String()
	if got := strings.Count(out, "outcome=unknown_challenge"); got != 3 {
		t.Fatalf("audit lines for unknown_challenge = %d, want 3; log:\n%s", got, out)
	}
	if !strings.Contains(out, "cid=_unknown") || strings.Contains(out, "\\xff") || strings.Contains(out, "\xff") {
		t.Fatalf("audit line must carry the folded cid only; log:\n%s", out)
	}
}

func isValidUTF8(s string) bool { return utf8.ValidString(s) }

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// Every route that takes a {cid} answers an id outside the grammar, and a
// well-formed id that is not in the catalog, with the same fixed 404 and does
// not reflect the input.
func TestUnknownCIDFixedBodyOnEveryCIDRoute(t *testing.T) {
	f := newSDFixture(t)
	// The routes come from the table the mux actually serves, so a new {cid}
	// route is covered without anyone editing a list.
	var routes []apispec.Route
	for _, rt := range f.srv.Routes() {
		if strings.Contains(rt.Pattern, "{cid}") {
			routes = append(routes, rt)
		}
	}
	if len(routes) < 6 {
		t.Fatalf("derived only %d {cid} routes from Routes(), want at least 6: %v", len(routes), routes)
	}
	ids := []string{"99-nope", outOfGrammarCIDs(1)[0], "bad%20id", "%ff%fe"}
	n := 0
	for _, rt := range routes {
		for i, cid := range ids {
			// A distinct seat per request, so no per-identity rate limiter can
			// turn a request away before the handler.
			n++
			u := fmt.Sprintf("user%d", n)
			email := ""
			if rt.Authz == apispec.AuthzAuthenticated || rt.Authz == apispec.AuthzSelfOrAdmin {
				email = u + "@ctf.local"
			}
			target := strings.NewReplacer("{cid}", cid, "{user}", u, "{idx}", "0").Replace(rt.Pattern)
			body := map[string]any{"user": u, "flag": "FALCO{x}", "condition": "evt.type=open", "checked": true}
			w := f.do(target, email, body)
			assertFixedUnknownBody(t, fmt.Sprintf("%s %s #%d", rt.Method, rt.Pattern, i), w.Code, w.Body.String(), cid)
		}
	}
}

// A catalog key that an older release's {cid} expression accepted but the
// challenge-id grammar does not (upper case, a dot) is no challenge: its path is
// the fixed 404 and its label is "_unknown", exactly like an id that is not in
// the catalog. (internal/catalog.Load never produces such a key; this holds the
// handler to the one grammar if a catalog is built by hand.)
func TestSubmitCatalogKeyOutsideTheGrammarIsStillUnknown(t *testing.T) {
	cat := catalog.Catalog{
		"AB.c":     {ID: "AB.c", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
		"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := scoreboard.NewHandler(cat, st, slog.New(slog.NewTextHandler(io.Discard, nil)),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain))
	before := submissions("_unknown", "unknown_challenge")
	r := httptest.NewRequest("POST", "/api/challenges/AB.c/submit", strings.NewReader(`{"user":"user1","flag":"FALCO{x}"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	assertFixedUnknownBody(t, "AB.c", w.Code, w.Body.String(), "AB.c")
	if got := submissions("_unknown", "unknown_challenge") - before; got != 1 {
		t.Fatalf("_unknown/unknown_challenge rose by %v, want 1", got)
	}
	if submissionLabelValues(t)["AB.c"] {
		t.Fatal("a key outside the grammar was used as a label value")
	}
}
