package scoreboard_test

// app#404 (ADR-0038): every identity gate refuses through ONE observation point,
// scoreboard_identity_denials_total{gate, reason}. These tests drive the real
// handler (scoreboard.NewHandler) and read the metric, so a gate that stops
// recording, records the wrong reason, or records twice fails here. V1 and V2
// derive their route sets from Routes() rather than listing routes.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// denialCounts reads every declared series.
func denialCounts() map[identityobs.Pair]float64 {
	out := map[identityobs.Pair]float64{}
	for _, p := range identityobs.Declared() {
		out[p] = testutil.ToFloat64(identityobs.DenialsTotal.WithLabelValues(string(p.Gate), string(p.Reason)))
	}
	return out
}

// moved returns the pairs whose counter changed between two snapshots, with the
// size of the change.
func moved(before, after map[identityobs.Pair]float64) map[identityobs.Pair]float64 {
	out := map[identityobs.Pair]float64{}
	for p, a := range after {
		if d := a - before[p]; d != 0 {
			out[p] = d
		}
	}
	return out
}

// expectedGate is which gate refuses a header-less request on rt: strict when
// the route is behind an identity-keyed bucket (the limiter answers first),
// otherwise the gate its Authz class names.
func expectedGate(t *testing.T, rt apispec.Route) identityobs.Gate {
	t.Helper()
	for _, b := range identityBuckets {
		for _, m := range b.members {
			if m == rt.MuxPattern() {
				return identityobs.GateStrict
			}
		}
	}
	switch rt.Authz {
	case apispec.AuthzSelfOrAdmin:
		return identityobs.GateSelfOrAdmin
	case apispec.AuthzAuthenticated:
		return identityobs.GateAuthenticated
	}
	t.Fatalf("%s: Authz %q has no identity gate", rt.MuxPattern(), rt.Authz)
	return ""
}

func identityGateRoutes(routes []apispec.Route) []apispec.Route {
	var out []apispec.Route
	for _, rt := range routes {
		if rt.Authz == apispec.AuthzSelfOrAdmin || rt.Authz == apispec.AuthzAuthenticated {
			out = append(out, rt)
		}
	}
	return out
}

// V1: every route behind an identity gate, header absent and blank, on a fresh
// handler each time (the board buckets are shared by two routes), is 403 and
// moves exactly one reason=no_identity series by exactly 1: the gate that
// refused. GET /portal is added by name (Authz none, the only route that shows
// the identity).
func TestIdentityDenials_EveryGateRouteCountsOnceAtItsOwnGate(t *testing.T) {
	routes := identityGateRoutes(newOriginFixture(t, []string{allowedOrigin}).Routes())
	if len(routes) < 10 {
		t.Fatalf("derived %d identity-gated routes: the derivation is broken, not clean", len(routes))
	}
	tried := 0
	gatesSeen := map[identityobs.Gate]bool{}
	for _, rt := range routes {
		for _, hdr := range []struct{ name, value string }{{"absent", ""}, {"blank", "   "}} {
			t.Run(rt.MuxPattern()+"/"+hdr.name, func(t *testing.T) {
				srv := newLimiterFixture(t, newTestClock())
				before := denialCounts()
				w := ogReq(t, srv, rt.Method, concretePath(rt.Pattern), allowedOrigin, "", hdr.value, strings.NewReader("{}"))
				if w.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403: %s", w.Code, w.Body)
				}
				got := moved(before, denialCounts())
				want := identityobs.Pair{Gate: expectedGate(t, rt), Reason: identityobs.ReasonNoIdentity}
				if len(got) != 1 || got[want] != 1 {
					t.Fatalf("series moved = %v, want exactly %v by 1 (a request is counted once, by the gate that refused it)", got, want)
				}
				gatesSeen[want.Gate] = true
			})
			tried++
		}
	}
	if tried != 2*len(routes) {
		t.Fatalf("tried %d requests for %d routes", tried, len(routes))
	}
	for _, g := range []identityobs.Gate{identityobs.GateStrict, identityobs.GateSelfOrAdmin, identityobs.GateAuthenticated} {
		if !gatesSeen[g] {
			t.Errorf("no route exercised gate %q: the derivation lost a whole gate", g)
		}
	}

	t.Run("GET /portal", func(t *testing.T) {
		for _, hdr := range []string{"", "   "} {
			srv := newLimiterFixture(t, newTestClock())
			before := denialCounts()
			w := ogReq(t, srv, "GET", "/portal", "", "", hdr, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("portal status = %d, want 200 (the shell is still served)", w.Code)
			}
			got := moved(before, denialCounts())
			want := identityobs.Pair{Gate: identityobs.GatePortal, Reason: identityobs.ReasonNoIdentity}
			if len(got) != 1 || got[want] != 1 {
				t.Fatalf("header %q: series moved = %v, want exactly %v by 1", hdr, got, want)
			}
		}
	})
}

// V2: the reason follows the header, per gate; admin and the caller's own
// requests record nothing.
func TestIdentityDenials_ReasonFollowsTheHeader(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	selfRoute := routeByPattern(t, srv.Routes(), "GET /api/users/{user}/me")
	boardRoute := routeByPattern(t, srv.Routes(), "GET /api/board/threads")
	if selfRoute.Authz != apispec.AuthzSelfOrAdmin || boardRoute.Authz != apispec.AuthzAuthenticated {
		t.Fatalf("fixture routes changed class: %s is %s, %s is %s", selfRoute.MuxPattern(), selfRoute.Authz, boardRoute.MuxPattern(), boardRoute.Authz)
	}
	g := func(gate identityobs.Gate, r identityobs.Reason) identityobs.Pair {
		return identityobs.Pair{Gate: gate, Reason: r}
	}
	for _, tc := range []struct {
		name  string
		route apispec.Route
		email string
		want  map[identityobs.Pair]float64 // nil = nothing recorded
		code  int
	}{
		{"self: the caller's own seat", selfRoute, "alice@ctf.local", nil, 200},
		{"self: an admin", selfRoute, "admin@ctf.local", nil, 200},
		{"self: another canonical seat", selfRoute, "bob@ctf.local", map[identityobs.Pair]float64{g(identityobs.GateSelfOrAdmin, identityobs.ReasonMismatch): 1}, 403},
		{"self: the right seat on another domain", selfRoute, "alice@evil.example", map[identityobs.Pair]float64{g(identityobs.GateSelfOrAdmin, identityobs.ReasonNonCanonical): 1}, 403},
		{"self: no @ at all", selfRoute, "alice", map[identityobs.Pair]float64{g(identityobs.GateSelfOrAdmin, identityobs.ReasonNonCanonical): 1}, 403},
		{"self: an upper-case canonical seat is lower-cased first", selfRoute, "ALICE@CTF.LOCAL", nil, 200},
		{"board: a canonical seat", boardRoute, "alice@ctf.local", nil, 200},
		{"board: a non-canonical identity", boardRoute, "alice@evil.example", map[identityobs.Pair]float64{g(identityobs.GateAuthenticated, identityobs.ReasonNonCanonical): 1}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := denialCounts()
			w := ogReq(t, srv, tc.route.Method, concretePath(tc.route.Pattern), allowedOrigin, "", tc.email, nil)
			if w.Code != tc.code {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.code, w.Body)
			}
			got := moved(before, denialCounts())
			if len(got) != len(tc.want) {
				t.Fatalf("series moved = %v, want %v", got, tc.want)
			}
			for p, v := range tc.want {
				if got[p] != v {
					t.Fatalf("series moved = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// V2, portal: admin and a canonical seat record nothing; absent / blank is
// no_identity; a header that is not a seat is non_canonical; always a 200, and
// the user the shell embeds is what it was before this metric existed.
func TestIdentityDenials_PortalReasonsAndUnchangedShell(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin})
	userJSON := regexp.MustCompile(`window\.__PORTAL_USER__ = ([^;\n]*);`)
	for _, tc := range []struct {
		name     string
		email    string
		want     map[identityobs.Pair]float64
		wantUser string
	}{
		{"admin", "admin@ctf.local", nil, `"admin"`},
		{"canonical seat", "alice@ctf.local", nil, `"alice"`},
		{"absent", "", map[identityobs.Pair]float64{{Gate: identityobs.GatePortal, Reason: identityobs.ReasonNoIdentity}: 1}, `""`},
		{"blank", "  ", map[identityobs.Pair]float64{{Gate: identityobs.GatePortal, Reason: identityobs.ReasonNoIdentity}: 1}, `""`},
		{"another domain", "alice@evil.example", map[identityobs.Pair]float64{{Gate: identityobs.GatePortal, Reason: identityobs.ReasonNonCanonical}: 1}, `""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := denialCounts()
			w := ogReq(t, srv, "GET", "/portal", "", "", tc.email, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			m := userJSON.FindStringSubmatch(w.Body.String())
			if m == nil || m[1] != tc.wantUser {
				t.Fatalf("__PORTAL_USER__ = %v, want %s", m, tc.wantUser)
			}
			got := moved(before, denialCounts())
			if len(got) != len(tc.want) {
				t.Fatalf("series moved = %v, want %v", got, tc.want)
			}
			for p, v := range tc.want {
				if got[p] != v {
					t.Fatalf("series moved = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// An unset EXPECTED_EMAIL_DOMAIN locks every participant out (fail-closed) and,
// until now, said nothing to the operator. It is non_canonical at both gates
// that judge the canonical form, and at the portal (ADR-0038 C7).
func TestIdentityDenials_EmptyExpectedEmailDomainIsNonCanonical(t *testing.T) {
	srv := newOriginFixture(t, []string{allowedOrigin}, scoreboard.WithExpectedEmailDomain(""))
	selfRoute := routeByPattern(t, srv.Routes(), "GET /api/users/{user}/me")
	boardRoute := routeByPattern(t, srv.Routes(), "GET /api/board/threads")
	for _, tc := range []struct {
		method, path string
		want         identityobs.Pair
	}{
		{"GET", concretePath(selfRoute.Pattern), identityobs.Pair{Gate: identityobs.GateSelfOrAdmin, Reason: identityobs.ReasonNonCanonical}},
		{"GET", concretePath(boardRoute.Pattern), identityobs.Pair{Gate: identityobs.GateAuthenticated, Reason: identityobs.ReasonNonCanonical}},
		{"GET", "/portal", identityobs.Pair{Gate: identityobs.GatePortal, Reason: identityobs.ReasonNonCanonical}},
	} {
		t.Run(string(tc.want.Gate), func(t *testing.T) {
			before := denialCounts()
			w := ogReq(t, srv, tc.method, tc.path, "", "", "alice@ctf.local", nil)
			if tc.want.Gate != identityobs.GatePortal && w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			if got := moved(before, denialCounts()); len(got) != 1 || got[tc.want] != 1 {
				t.Fatalf("series moved = %v, want exactly %v by 1", got, tc.want)
			}
		})
	}
}

// loggedFixture is newOriginFixture with a JSON logger the test can read.
func loggedFixture(t *testing.T, buf *bytes.Buffer) *scoreboard.Handler {
	t.Helper()
	cat := catalog.Catalog{"02-evade": {ID: "02-evade", Type: "evade", ForbiddenRules: []string{"r"}, ExpectedFlag: "FALCO{ok}"}}
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	boardSt, err := board.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { boardSt.Close() })
	return scoreboard.NewHandler(cat, st, slog.New(slog.NewJSONHandler(buf, nil)),
		scoreboard.WithExpectedEmailDomain(fixtureEmailDomain),
		scoreboard.WithAdminEmails([]string{"admin@ctf.local"}),
		scoreboard.WithAllowedOrigins([]string{allowedOrigin}),
		scoreboard.WithBoard(boardSt),
	)
}

// V4 (d), end to end: whichever gate refuses, the log has only the one message,
// and neither the caller's email nor the path (a participant's name) is in it.
// The old per-gate lines are gone.
func TestIdentityDenials_LogCarriesNeitherIdentityNorPath(t *testing.T) {
	const (
		emailSentinel = "sentinelperson@ctf.local" // a valid seat slug, so the gate says mismatch
		seatSentinel  = "sentinel-victim"
	)
	var buf bytes.Buffer
	srv := loggedFixture(t, &buf)
	for _, req := range []struct{ method, path, email string }{
		{"GET", "/api/users/" + seatSentinel + "/me", emailSentinel},         // self_or_admin, mismatch
		{"GET", "/api/users/" + seatSentinel + "/me", ""},                    // self_or_admin, no_identity
		{"GET", "/api/board/threads", "sentinel.person@evil.example"},        // authenticated, non_canonical
		{"GET", "/api/board/threads", ""},                                    // authenticated, no_identity
		{"POST", "/api/users/" + seatSentinel + "/profile", ""},              // strict (needs an Origin)
		{"GET", "/portal?q=" + seatSentinel, "sentinel.person@evil.example"}, // portal, non_canonical
	} {
		origin := ""
		if req.method == "POST" {
			origin = allowedOrigin
		}
		ogReq(t, srv, req.method, req.path, origin, "", req.email, strings.NewReader("{}"))
	}
	var gates []string
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("not JSON: %q", ln)
		}
		if m["msg"] != "identity gate denied" {
			t.Errorf("unexpected log line (the per-gate lines were replaced by the one message): %s", ln)
			continue
		}
		gates = append(gates, m["gate"].(string)+"/"+m["reason"].(string))
	}
	sort.Strings(gates)
	want := []string{"authenticated/no_identity", "authenticated/non_canonical", "portal/non_canonical", "self_or_admin/mismatch", "self_or_admin/no_identity", "strict/no_identity"}
	if strings.Join(gates, ",") != strings.Join(want, ",") {
		t.Errorf("log lines by gate/reason = %v, want %v (one per (gate, reason) inside the 10s window)", gates, want)
	}
	for _, bad := range []string{"sentinel", "ctf.local"} {
		if strings.Contains(buf.String(), bad) {
			t.Errorf("the log contains %q: %s", bad, buf.String())
		}
	}
}

// V3: right after the production handler is assembled, before any request, the
// metric has exactly the 8 declared series (every gate has a no_identity one),
// and ratelimit_identity_requests_total has no no_identity series at all.
func TestIdentityDenials_SeriesPregeneratedAndOldOutcomeGone(t *testing.T) {
	newLimiterFixture(t, newTestClock())
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	denials := map[identityobs.Pair]bool{}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "scoreboard_identity_denials_total":
			for _, m := range mf.GetMetric() {
				var p identityobs.Pair
				for _, lp := range m.GetLabel() {
					switch lp.GetName() {
					case "gate":
						p.Gate = identityobs.Gate(lp.GetValue())
					case "reason":
						p.Reason = identityobs.Reason(lp.GetValue())
					}
				}
				denials[p] = true
			}
		case "ratelimit_identity_requests_total":
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "outcome" && lp.GetValue() != "allowed" && lp.GetValue() != "limited" {
						t.Errorf("ratelimit_identity_requests_total has outcome %q: only allowed and limited remain (app#404)", lp.GetValue())
					}
				}
			}
		}
	}
	if len(denials) != 8 {
		t.Fatalf("scoreboard_identity_denials_total has %d series %v, want the 8 declared", len(denials), denials)
	}
	for _, p := range identityobs.Declared() {
		if !denials[p] {
			t.Errorf("series %v is missing before any request", p)
		}
	}
}
