package identityobs_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

const (
	metricName  = "scoreboard_identity_denials_total"
	logMessage  = "identity gate denied"
	pkgImport   = "github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	declaredVar = "declared"
)

// wantDeclared is ADR-0038 D2's table, written out a second time on purpose:
// the code's own table cannot be the oracle for itself.
var wantDeclared = []identityobs.Pair{
	{Gate: "strict", Reason: "no_identity"},
	{Gate: "self_or_admin", Reason: "no_identity"},
	{Gate: "self_or_admin", Reason: "non_canonical"},
	{Gate: "self_or_admin", Reason: "mismatch"},
	{Gate: "authenticated", Reason: "no_identity"},
	{Gate: "authenticated", Reason: "non_canonical"},
	{Gate: "portal", Reason: "no_identity"},
	{Gate: "portal", Reason: "non_canonical"},
}

func pairStrings(ps []identityobs.Pair) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p.Gate)+"/"+string(p.Reason))
	}
	sort.Strings(out)
	return out
}

// gatheredPairs is the (gate, reason) label sets the default registry holds for
// the metric right now, with their values.
func gatheredPairs(t *testing.T) map[string]float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			var g, r string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "gate":
					g = lp.GetValue()
				case "reason":
					r = lp.GetValue()
				default:
					t.Errorf("%s has an unexpected label %q (only gate and reason are allowed)", metricName, lp.GetName())
				}
			}
			out[g+"/"+r] = m.GetCounter().GetValue()
		}
	}
	return out
}

func count(g identityobs.Gate, r identityobs.Reason) float64 {
	return testutil.ToFloat64(identityobs.DenialsTotal.WithLabelValues(string(g), string(r)))
}

// V3: the 8 series exist before anything was recorded, each a series (so
// increase() sees the first denial) and in particular reason=no_identity for
// every gate. Nothing else exists.
func TestDeclaredSeriesExistAtStart(t *testing.T) {
	if got, want := pairStrings(identityobs.Declared()), pairStrings(wantDeclared); !reflect.DeepEqual(got, want) {
		t.Fatalf("Declared() = %v, want %v (ADR-0038 D2)", got, want)
	}
	got := gatheredPairs(t)
	if len(got) != 8 {
		t.Fatalf("%s has %d series %v, want exactly the 8 declared", metricName, len(got), got)
	}
	for _, p := range wantDeclared {
		if _, ok := got[string(p.Gate)+"/"+string(p.Reason)]; !ok {
			t.Errorf("series gate=%q reason=%q is missing at start", p.Gate, p.Reason)
		}
	}
	for _, g := range []identityobs.Gate{identityobs.GateStrict, identityobs.GateSelfOrAdmin, identityobs.GateAuthenticated, identityobs.GatePortal} {
		if _, ok := got[string(g)+"/no_identity"]; !ok {
			t.Errorf("gate %q has no reason=\"no_identity\" series: a missing series would read as \"cannot judge\" to platform", g)
		}
	}
}

func req(pattern, remote string, hdr map[string][]string) *http.Request {
	r := httptest.NewRequest("POST", "/api/users/victim-seat/x?q=query-sentinel", nil)
	r.Pattern = pattern
	r.RemoteAddr = remote
	for k, vs := range hdr {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time { return c.t }

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", ln, err)
		}
		out = append(out, m)
	}
	return out
}

func newObs(buf *bytes.Buffer, clock *fixedClock) *identityobs.Observer {
	return identityobs.New(slog.New(slog.NewJSONHandler(buf, nil)), clock.now)
}

// V4 (a): the first denial per (gate, reason) writes exactly one line, whose
// keys are time, level, msg and the six fields, and nothing else.
func TestLogHasExactlySixFields(t *testing.T) {
	var buf bytes.Buffer
	o := newObs(&buf, &fixedClock{time.Unix(1000, 0)})
	o.Record(req("POST /api/users/{user}/x", "10.1.2.3:51000", nil), identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity)
	ls := lines(t, &buf)
	if len(ls) != 1 {
		t.Fatalf("want 1 line, got %d: %s", len(ls), buf.String())
	}
	got := ls[0]
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	wantKeys := []string{"gate", "header", "level", "msg", "reason", "remote_addr", "route", "suppressed", "time"}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("log keys = %v, want %v (line: %s)", keys, wantKeys, buf.String())
	}
	want := map[string]any{
		"level": "WARN", "msg": logMessage, "gate": "self_or_admin", "reason": "no_identity",
		"route": "POST /api/users/{user}/x", "remote_addr": "10.1.2.3", "header": "absent", "suppressed": float64(0),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("log[%q] = %v, want %v", k, got[k], v)
		}
	}
}

// The header field distinguishes absent, blank and present; the route falls
// back to "-" and IPv6 loses its port and brackets (V4 (e)).
func TestLogHeaderStateRouteAndRemote(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hdr        map[string][]string
		pattern    string
		remote     string
		wantHeader string
		wantRoute  string
		wantRemote string
	}{
		{"absent", nil, "GET /p", "10.0.0.1:1", "absent", "GET /p", "10.0.0.1"},
		{"blank is whitespace only", map[string][]string{"X-Auth-Request-Email": {"   "}}, "", "[::1]:9", "blank", "-", "::1"},
		{"present", map[string][]string{"X-Auth-Request-Email": {"someone@elsewhere.example"}}, "GET /p", "192.0.2.5:80", "present", "GET /p", "192.0.2.5"},
		{"remote without a port is kept as is", nil, "GET /p", "no-port", "absent", "GET /p", "no-port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			o := newObs(&buf, &fixedClock{time.Unix(1000, 0)})
			o.Record(req(tc.pattern, tc.remote, tc.hdr), identityobs.GateAuthenticated, identityobs.ReasonNoIdentity)
			ls := lines(t, &buf)
			if len(ls) != 1 {
				t.Fatalf("want 1 line, got %s", buf.String())
			}
			if ls[0]["header"] != tc.wantHeader || ls[0]["route"] != tc.wantRoute || ls[0]["remote_addr"] != tc.wantRemote {
				t.Fatalf("header/route/remote_addr = %v/%v/%v, want %v/%v/%v", ls[0]["header"], ls[0]["route"], ls[0]["remote_addr"], tc.wantHeader, tc.wantRoute, tc.wantRemote)
			}
		})
	}
}

// V4 (b): inside 10 seconds the same (gate, reason) is silent; after it the
// line carries how many were swallowed. The metric still counts every one.
func TestLogIsSampledPerGateAndReason(t *testing.T) {
	var buf bytes.Buffer
	clock := &fixedClock{time.Unix(1000, 0)}
	o := newObs(&buf, clock)
	before := count(identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity)
	deny := func(n int) {
		for i := 0; i < n; i++ {
			o.Record(req("POST /p", "10.0.0.1:1", nil), identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity)
		}
	}
	deny(25)
	if n := len(lines(t, &buf)); n != 1 {
		t.Fatalf("25 denials in one instant: %d lines, want 1", n)
	}
	clock.t = clock.t.Add(10*time.Second - time.Nanosecond)
	deny(5)
	if n := len(lines(t, &buf)); n != 1 {
		t.Fatalf("just inside the window: %d lines, want 1", n)
	}
	clock.t = clock.t.Add(time.Nanosecond)
	deny(1)
	ls := lines(t, &buf)
	if len(ls) != 2 {
		t.Fatalf("after the window: %d lines, want 2\n%s", len(ls), buf.String())
	}
	if ls[1]["suppressed"] != float64(29) { // 24 + 5 swallowed
		t.Fatalf("resumed line suppressed = %v, want 29", ls[1]["suppressed"])
	}
	if d := count(identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity) - before; d != 31 {
		t.Fatalf("metric delta = %v, want 31 (sampling is log-only)", d)
	}
}

// V4 (c): a flood of one reason does not hide the first line of another reason
// on the same gate, nor of the same reason on another gate.
func TestSamplingKeyIsGateAndReason(t *testing.T) {
	var buf bytes.Buffer
	o := newObs(&buf, &fixedClock{time.Unix(1000, 0)})
	r := func() *http.Request { return req("POST /p", "10.0.0.1:1", nil) }
	for i := 0; i < 50; i++ {
		o.Record(r(), identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity)
	}
	o.Record(r(), identityobs.GateSelfOrAdmin, identityobs.ReasonMismatch)
	o.Record(r(), identityobs.GateAuthenticated, identityobs.ReasonNoIdentity)
	ls := lines(t, &buf)
	if len(ls) != 3 {
		t.Fatalf("%d lines, want 3 (one per (gate, reason)):\n%s", len(ls), buf.String())
	}
	seen := map[string]bool{}
	for _, l := range ls {
		seen[l["gate"].(string)+"/"+l["reason"].(string)] = true
	}
	for _, k := range []string{"self_or_admin/no_identity", "self_or_admin/mismatch", "authenticated/no_identity"} {
		if !seen[k] {
			t.Errorf("no line for %s: %v", k, seen)
		}
	}
}

// The log ceiling does not depend on traffic: every declared pair, hammered for
// a minute of simulated time, writes at most one line per 10 seconds.
func TestLogCeilingIsEightPairsPerWindow(t *testing.T) {
	var buf bytes.Buffer
	clock := &fixedClock{time.Unix(1000, 0)}
	o := newObs(&buf, clock)
	for sec := 0; sec < 60; sec++ {
		clock.t = time.Unix(1000, 0).Add(time.Duration(sec) * time.Second)
		for _, p := range identityobs.Declared() {
			for i := 0; i < 100; i++ {
				o.Record(req("POST /p", "10.0.0.1:1", nil), p.Gate, p.Reason)
			}
		}
	}
	if n, max := len(lines(t, &buf)), 8*6; n != max {
		t.Fatalf("%d lines for 60s of load on 8 pairs, want %d (one per pair per 10s)", n, max)
	}
}

// V4 (d): no value of the identity header, no path (and so no path parameter),
// no query, no cookie, no forwarded-for address reaches the log, whichever
// reason is recorded and however the header looks.
func TestLogNeverContainsIdentityPathQueryOrForwardedAddress(t *testing.T) {
	const (
		emailSentinel = "sentinel-person@sentinel-domain.example"
		pathSentinel  = "sentinel-user-seat"
	)
	hdr := map[string][]string{
		"X-Auth-Request-Email": {emailSentinel},
		"Cookie":               {"sess=sentinel-cookie"},
		"X-Forwarded-For":      {"198.51.100.99"},
		"Cf-Connecting-Ip":     {"198.51.100.98"},
	}
	for _, p := range identityobs.Declared() {
		var buf bytes.Buffer
		o := newObs(&buf, &fixedClock{time.Unix(1000, 0)})
		r := httptest.NewRequest("GET", "/api/users/"+pathSentinel+"/me?q=sentinel-query", nil)
		r.Pattern, r.RemoteAddr = "GET /api/users/{user}/me", "10.9.8.7:4444"
		for k, vs := range hdr {
			r.Header[k] = vs
		}
		r.SetPathValue("user", pathSentinel)
		o.Record(r, p.Gate, p.Reason)
		if buf.Len() == 0 {
			t.Fatalf("%v: no line written", p)
		}
		for _, bad := range []string{"sentinel", "198.51.100", pathSentinel, "ctf.local"} {
			if strings.Contains(buf.String(), bad) {
				t.Errorf("%v: log contains %q: %s", p, bad, buf.String())
			}
		}
	}
}

// StrictNoIdentity records the strict gate's no_identity; Portal picks the
// reason from the header.
func TestShorthandsPickTheirGateAndReason(t *testing.T) {
	o := identityobs.New(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), nil)

	before := count(identityobs.GateStrict, identityobs.ReasonNoIdentity)
	o.StrictNoIdentity(req("POST /p", "10.0.0.1:1", nil))
	if d := count(identityobs.GateStrict, identityobs.ReasonNoIdentity) - before; d != 1 {
		t.Fatalf("StrictNoIdentity moved strict/no_identity by %v, want 1", d)
	}

	for _, tc := range []struct {
		name string
		hdr  map[string][]string
		want identityobs.Reason
	}{
		{"absent", nil, identityobs.ReasonNoIdentity},
		{"blank", map[string][]string{ratelimit.IdentityHeader: {"  "}}, identityobs.ReasonNoIdentity},
		{"present but not a seat", map[string][]string{ratelimit.IdentityHeader: {"x@other.example"}}, identityobs.ReasonNonCanonical},
	} {
		t.Run("portal/"+tc.name, func(t *testing.T) {
			other := identityobs.ReasonNoIdentity
			if tc.want == identityobs.ReasonNoIdentity {
				other = identityobs.ReasonNonCanonical
			}
			b, bo := count(identityobs.GatePortal, tc.want), count(identityobs.GatePortal, other)
			o.Portal(req("GET /portal", "10.0.0.1:1", tc.hdr))
			if d := count(identityobs.GatePortal, tc.want) - b; d != 1 {
				t.Errorf("portal/%s moved by %v, want 1", tc.want, d)
			}
			if d := count(identityobs.GatePortal, other) - bo; d != 0 {
				t.Errorf("portal/%s moved by %v, want 0", other, d)
			}
		})
	}
}

// An undeclared pair is a programming error and never becomes a series or a
// sampling key.
func TestUndeclaredPairPanicsAndCreatesNothing(t *testing.T) {
	o := identityobs.New(slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), nil)
	for _, p := range []identityobs.Pair{
		{Gate: identityobs.GateStrict, Reason: identityobs.ReasonNonCanonical}, // declared gate and reason, undeclared pair
		{Gate: identityobs.GatePortal, Reason: identityobs.ReasonMismatch},
		{Gate: "admin", Reason: identityobs.ReasonNoIdentity},
		{Gate: "", Reason: ""},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Record(%v) did not panic", p)
				}
			}()
			o.Record(req("GET /p", "10.0.0.1:1", nil), p.Gate, p.Reason)
		}()
	}
	if got := gatheredPairs(t); len(got) != 8 {
		t.Fatalf("after rejected pairs the metric has %d series %v, want still the 8 declared", len(got), got)
	}
}

// The zero Observer works (slog.Default and time.Now at use time).
func TestZeroObserverIsUsable(t *testing.T) {
	var o identityobs.Observer
	before := count(identityobs.GateAuthenticated, identityobs.ReasonNonCanonical)
	o.Record(req("GET /p", "10.0.0.1:1", nil), identityobs.GateAuthenticated, identityobs.ReasonNonCanonical)
	if d := count(identityobs.GateAuthenticated, identityobs.ReasonNonCanonical) - before; d != 1 {
		t.Fatalf("delta = %v, want 1", d)
	}
}

// --- V6: the vocabulary ------------------------------------------------------

// moduleRoot finds the directory holding go.mod above this test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// vocabularyConstants parses identityobs.go for its Gate and Reason constants.
func vocabularyConstants(t *testing.T, root string) (names []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "internal/scoreboard/identityobs/identityobs.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			ty, ok := vs.Type.(*ast.Ident)
			if !ok || (ty.Name != "Gate" && ty.Name != "Reason") {
				continue
			}
			for _, n := range vs.Names {
				names = append(names, n.Name)
			}
		}
	}
	return names
}

// usesOfVocabulary counts, per constant name, its uses in NON-test code outside
// the declaration of the constant and outside the `declared` table: an in-package
// identifier in identityobs' own files, a identityobs.X selector everywhere else.
// A constant used only by the table that declares it is a word nothing says.
func usesOfVocabulary(t *testing.T, root string, names []string) map[string]int {
	t.Helper()
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	uses := map[string]int{}
	fset := token.NewFileSet()
	for _, top := range []string{"cmd", "internal"} {
		if _, err := os.Stat(filepath.Join(root, top)); os.IsNotExist(err) {
			continue // a synthetic module in the mutation test has no cmd/
		}
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			own := f.Name.Name == "identityobs" && strings.Contains(filepath.ToSlash(path), "internal/scoreboard/identityobs/")
			importsPkg := false
			for _, im := range f.Imports {
				if strings.Trim(im.Path.Value, `"`) == pkgImport {
					importsPkg = true
				}
			}
			if !own && !importsPkg {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.GenDecl:
					if own && x.Tok == token.CONST {
						return false // the declarations themselves
					}
					if own && x.Tok == token.VAR {
						for _, sp := range x.Specs {
							if vs, ok := sp.(*ast.ValueSpec); ok && len(vs.Names) == 1 && vs.Names[0].Name == declaredVar {
								return false // the table
							}
						}
					}
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "identityobs" && want[x.Sel.Name] {
						uses[x.Sel.Name]++
					}
				case *ast.Ident:
					if own && want[x.Name] {
						uses[x.Name]++
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return uses
}

// V6: every Gate and Reason constant is used by non-test code outside the table
// that declares the pairs, and the table is a set of (declared gate, declared
// reason) pairs without duplicates.
func TestVocabularyHasNoUnusedWord(t *testing.T) {
	root := moduleRoot(t)
	names := vocabularyConstants(t, root)
	if len(names) == 0 {
		t.Fatal("parsed 0 Gate/Reason constants: the parse is broken, not clean")
	}
	uses := usesOfVocabulary(t, root, names)
	for _, n := range names {
		if uses[n] == 0 {
			t.Errorf("identityobs.%s is never used by non-test code outside the declared table: a vocabulary word nothing says (ADR-0038 D2/V6)", n)
		}
	}
	seen := map[identityobs.Pair]bool{}
	for _, p := range identityobs.Declared() {
		if seen[p] {
			t.Errorf("pair %v is declared twice", p)
		}
		seen[p] = true
	}
}

// The V6 check is not vacuous: in a module where a Gate constant is declared
// (and listed in the table) but nothing else uses it, it reports 0 uses; the
// one that something uses is counted.
func TestVocabularyCheckCatchesAnUnusedWord(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "scoreboard", "identityobs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package identityobs

type Gate string

const (
	GateUsed   Gate = "used"
	GateUnused Gate = "unused"
)

var declared = []Gate{GateUsed, GateUnused}

func Use() Gate { return GateUsed }
`
	if err := os.WriteFile(filepath.Join(dir, "identityobs.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	names := vocabularyConstants(t, root)
	if len(names) != 2 {
		t.Fatalf("parsed %v, want the two constants", names)
	}
	uses := usesOfVocabulary(t, root, names)
	if uses["GateUsed"] == 0 || uses["GateUnused"] != 0 {
		t.Fatalf("uses = %v, want GateUsed > 0 and GateUnused == 0", uses)
	}
}

// A nil *Observer (a handler assembled by hand) still counts instead of
// panicking in the middle of a request.
func TestNilObserverStillCounts(t *testing.T) {
	var o *identityobs.Observer
	before := count(identityobs.GatePortal, identityobs.ReasonNoIdentity)
	o.Portal(req("GET /portal", "10.0.0.1:1", nil))
	if d := count(identityobs.GatePortal, identityobs.ReasonNoIdentity) - before; d != 1 {
		t.Fatalf("delta = %v, want 1", d)
	}
}

// referencesOutside lists the non-test files outside identityobs that mention
// identityobs.<name>.
func referencesOutside(t *testing.T, root, name string) []string {
	t.Helper()
	var files []string
	fset := token.NewFileSet()
	for _, top := range []string{"cmd", "internal"} {
		if _, err := os.Stat(filepath.Join(root, top)); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			if strings.Contains(filepath.ToSlash(path), "internal/scoreboard/identityobs/") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "identityobs" && sel.Sel.Name == name {
						files = append(files, path)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// V6: the counter is incremented in one place. A gate that did
// identityobs.DenialsTotal.WithLabelValues(...).Inc() itself would skip the
// declared-pair check and the sampled log; every gate goes through Record.
// (Test code reads the counter; that is the point of exporting it.)
func TestNothingOutsideIncrementsDenialsTotalDirectly(t *testing.T) {
	if got := referencesOutside(t, moduleRoot(t), "DenialsTotal"); len(got) > 0 {
		t.Fatalf("non-test code outside identityobs references identityobs.DenialsTotal: %v (record through Observer.Record)", got)
	}
	// Not vacuous: a synthetic gate that increments it directly is found.
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "scoreboard", "api")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package api\n\nimport \"" + pkgImport + "\"\n\nfunc deny() { identityobs.DenialsTotal.WithLabelValues(\"strict\", \"no_identity\").Inc() }\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := referencesOutside(t, root, "DenialsTotal"); len(got) != 1 {
		t.Fatalf("the synthetic direct increment was not found: %v", got)
	}
}
