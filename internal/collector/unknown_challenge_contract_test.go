package collector

// ADR-0041 V5: the collector's own 404 (an id outside the challenge-id grammar)
// and the scoreboard's 404 (an id inside it that is not a challenge) are the same
// bytes. The two are separate definitions in production (the collector links no
// scoreboard code), so this composition test is what holds them together: it puts
// the collector in front of the REAL scoreboard handler built on the REAL
// challenges/ catalog. The scoreboard import is test-only, so the collector's
// production closure is unchanged (internal/apispec/dependency_boundary_test.go
// scans non-test files only).

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

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
	const probe = "99-verify-probe"
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
