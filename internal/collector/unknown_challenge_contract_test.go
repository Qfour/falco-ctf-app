package collector

// ADR-0041 V5: the collector's own 404 (an id outside the challenge-id grammar)
// and the scoreboard's 404 (an id inside it that is not a challenge) are the same
// bytes. The two are separate definitions in production (the collector links no
// scoreboard code), so this composition test is what holds them together: it puts
// the collector in front of the REAL scoreboard handler built on the REAL
// challenges/ catalog. The scoreboard import is test-only, so the collector's
// production closure is unchanged (internal/apispec/dependency_boundary_test.go
// scans non-test files only).
//
// This file holds ALL of ADR-0041's contract tests that name the verify probe
// (V1, V2, V3, V5), so the probe id is read from ONE place: the contract table's
// row in .claude/rules/falco-ctf-app-conventions.md (verifyProbe), not written
// again in each test (app#486: it was a literal in six places).

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// verifyProbe returns the id platform's verify (a-2) submits through the
// collector (platform #264, ADR-0041), read from the contract table row "challenge
// id の文法と collector の 404" (`POST /api/challenges/<probe>/submit`). The row is
// what platform reads, so the tests follow it; the collector spec must name the
// same id. Changing the probe is a contract change (both repos).
func verifyProbe(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".claude", "rules", "falco-ctf-app-conventions.md"))
	if err != nil {
		t.Fatalf("the contract table: %v", err)
	}
	re := regexp.MustCompile("POST /api/challenges/([^/\\s`]+)/submit")
	var probe string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "| challenge id の文法と collector の 404") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("the contract row names no `POST /api/challenges/<probe>/submit`: %.120s", line)
		}
		probe = m[1]
		break
	}
	if probe == "" {
		t.Fatal("the contract table has no row \"challenge id の文法と collector の 404\": the probe cannot be read")
	}
	spec, err := os.ReadFile(filepath.Join("..", "..", "docs", "openapi-collector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(spec), "`"+probe+"`") {
		t.Fatalf("docs/openapi-collector.yaml does not name the probe `%s` of the contract row", probe)
	}
	return probe
}

// V1 + V2 + V3: the probe is INSIDE the grammar (the collector answers an id outside
// it with its own 404 and forwards nothing, so the gate would go green without
// reaching the scoreboard) and the old probe `verify-probe` stays outside it; it is
// not a challenge of the real challenges/ catalog; the collector forwards it; the
// scoreboard answers 404 with the fixed body whose prefix verify.sh (a-2) matches.
func TestVerifyProbeContract(t *testing.T) {
	probe := verifyProbe(t)
	if !challengeid.Valid(probe) {
		t.Fatalf("%s is outside the grammar %s: the collector would answer it itself", probe, challengeid.Pattern)
	}
	if challengeid.Valid("verify-probe") {
		t.Fatalf("the old probe id verify-probe must stay outside the grammar %s (it is what made the gate pass on the collector's own 404)", challengeid.Pattern)
	}
	cat, err := catalog.Load(filepath.Join("..", "..", "challenges"))
	if err != nil {
		t.Fatalf("catalog.Load(challenges): %v", err)
	}
	if len(cat) == 0 {
		t.Fatal("the real catalog is empty: the not-a-key check would prove nothing")
	}
	if _, ok := cat[probe]; ok {
		t.Fatalf("%s is a challenge in challenges/: the gate's probe would be a real id", probe)
	}

	// V1: the collector forwards it (an upstream recorder, no scoreboard).
	c, up := newTestCollector(t)
	resp := do(t, "POST", c.URL+"/api/challenges/"+probe+"/submit", `{}`)
	resp.Body.Close()
	if got, want := up.last(), "POST /api/challenges/"+probe+"/submit"; got != want {
		t.Fatalf("upstream call = %q, want %q (a grammar-valid id that is not a challenge must be forwarded)", got, want)
	}

	// V3: what the gate sends to the scoreboard (header-less, no Origin).
	st, err := store.Open(filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sb := scoreboard.NewHandler(cat, st, slog.New(slog.NewTextHandler(io.Discard, nil)),
		scoreboard.WithExpectedEmailDomain("ctf.local"))
	r := httptest.NewRequest("POST", "/api/challenges/"+probe+"/submit", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	sb.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || !strings.HasPrefix(w.Body.String(), `{"error":"unknown challenge`) {
		t.Fatalf("scoreboard answered %d %q, want 404 with the prefix verify.sh (a-2) matches", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), probe) {
		t.Fatalf("the 404 body reflects the id: %q", w.Body.String())
	}
}

type observed struct {
	status int
	ct     string
	body   string
}

func TestUnknownChallenge404_CollectorAndScoreboardAreByteIdentical(t *testing.T) {
	cat, err := catalog.Load(filepath.Join("..", "..", "challenges"))
	if err != nil {
		t.Fatalf("catalog.Load(challenges): %v", err)
	}
	if len(cat) == 0 {
		t.Fatal("the real catalog is empty: the not-a-key check below would prove nothing")
	}
	probe := verifyProbe(t)
	if _, ok := cat[probe]; ok {
		t.Fatalf("%s is a challenge in challenges/: it would not be an unknown id", probe)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "v5.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sb := scoreboard.NewHandler(cat, st, slog.New(slog.NewTextHandler(io.Discard, nil)),
		scoreboard.WithExpectedEmailDomain("ctf.local"))
	var upstreamCalls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		sb.ServeHTTP(w, r)
	}))
	t.Cleanup(up.Close)

	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	h, err := New(up.URL, testLogger(), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := httptest.NewServer(h)
	t.Cleanup(c.Close)

	post := func(cid string) observed {
		t.Helper()
		resp := do(t, "POST", c.URL+"/api/challenges/"+cid+"/submit", `{"user":"user1","flag":"FALCO{x}"}`)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return observed{resp.StatusCode, resp.Header.Get("Content-Type"), string(b)}
	}

	// (i) ids outside the grammar are answered by the collector; the scoreboard is never called.
	var local observed
	for i, cid := range []string{"AB.c", "verify-probe"} {
		before := upstreamCalls.Load()
		got := post(cid)
		if n := upstreamCalls.Load() - before; n != 0 {
			t.Fatalf("%s: the scoreboard was called %d time(s); a grammar-external id must stop at the collector", cid, n)
		}
		if got.status != http.StatusNotFound {
			t.Fatalf("%s: status = %d body=%.120s, want 404", cid, got.status, got.body)
		}
		if i == 0 {
			local = got
		} else if got != local {
			t.Fatalf("%s: %+v differs from %+v: the collector's own 404 must not depend on the id", cid, got, local)
		}
	}

	// (ii) the probe is inside the grammar: forwarded, and the scoreboard answers 404.
	before := upstreamCalls.Load()
	remote := post(probe)
	if n := upstreamCalls.Load() - before; n != 1 {
		t.Fatalf("%s: the scoreboard was called %d time(s), want exactly 1 (a grammar-valid id must be forwarded)", probe, n)
	}
	if remote.status != http.StatusNotFound {
		t.Fatalf("%s: status = %d body=%.120s, want the scoreboard's 404", probe, remote.status, remote.body)
	}
	if !strings.HasPrefix(remote.body, `{"error":"unknown challenge`) {
		t.Fatalf("%s: body %q lacks the prefix platform verify (a-2) matches", probe, remote.body)
	}

	// (iii) the two answers are the same, byte for byte (status, Content-Type, body).
	if remote != local {
		t.Fatalf("the collector's 404 and the scoreboard's 404 differ:\n collector  %+v\n scoreboard %+v", local, remote)
	}
}
