package api

// ADR-0056 A3b-4 / V38: Authz: self records its refusals at its own gate,
// scoreboard_identity_denials_total{gate="self"}, and Authz: self-or-admin keeps
// gate="self_or_admin". The two gates share ONE judgement (judgeSelf), so the header's
// normalisation, the equality and the reason cannot drift apart.
//
// The route-level counts (an answer request through Routes()) are in
// internal/scoreboard/answer_route_test.go; a header-less request to that route is
// refused by the strict limiter in front (gate="strict"), so the gate="self" /
// no_identity series is only reachable from selfOnly itself, which is what is driven
// here.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
)

const (
	selfGateDomain = "ctf.local"
	selfGateAdmin  = "admin@ctf.local"   // an ADMIN_EMAILS identity that is also a canonical seat form
	selfGateStaff  = "ops@staff.example" // an ADMIN_EMAILS identity on another domain
)

func selfGateHandler() *Handler {
	return &Handler{
		adminSet:    newAdminSet([]string{selfGateAdmin, selfGateStaff}),
		emailDomain: selfGateDomain,
		denials:     identityobs.New(slog.New(slog.NewJSONHandler(io.Discard, nil)), nil),
	}
}

func selfGateCounts() map[identityobs.Pair]float64 {
	out := map[identityobs.Pair]float64{}
	for _, p := range identityobs.Declared() {
		out[p] = testutil.ToFloat64(identityobs.DenialsTotal.WithLabelValues(string(p.Gate), string(p.Reason)))
	}
	return out
}

func selfGateMoved(before map[identityobs.Pair]float64) map[identityobs.Pair]float64 {
	out := map[identityobs.Pair]float64{}
	for p, a := range selfGateCounts() {
		if d := a - before[p]; d != 0 {
			out[p] = d
		}
	}
	return out
}

// selfGateRequest is a request for {user}=alice carrying email as the identity header;
// set=false leaves the header out altogether.
func selfGateRequest(email string, set bool) *http.Request {
	r := httptest.NewRequest("POST", "/api/users/alice/x", nil)
	if set {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	return r
}

type selfGateCase struct {
	name   string
	email  string
	set    bool
	reason identityobs.Reason // "" = passes
}

func TestSelfOnly_RefusalsAreCountedAtGateSelf(t *testing.T) {
	for _, tc := range []selfGateCase{
		{"no header", "", false, identityobs.ReasonNoIdentity},
		{"a blank header", "   ", true, identityobs.ReasonNoIdentity},
		{"the right seat on another domain", "alice@evil.example", true, identityobs.ReasonNonCanonical},
		{"no @ at all", "alice", true, identityobs.ReasonNonCanonical},
		{"another canonical seat", "bob@ctf.local", true, identityobs.ReasonMismatch},
		{"an ADMIN_EMAILS identity on the seat domain", selfGateAdmin, true, identityobs.ReasonMismatch},
		{"an ADMIN_EMAILS identity on another domain (intended refusal, not non_canonical)", selfGateStaff, true, identityobs.ReasonMismatch},
		{"the seat itself", "alice@ctf.local", true, ""},
		{"the seat itself, upper case", "ALICE@CTF.LOCAL", true, ""},
		{"the seat itself, padded", "  alice@ctf.local ", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := selfGateCounts()
			w := httptest.NewRecorder()
			ok := selfGateHandler().selfOnly(w, selfGateRequest(tc.email, tc.set), "alice")
			got := selfGateMoved(before)
			if tc.reason == "" {
				if !ok || len(got) != 0 {
					t.Fatalf("ok=%v, series moved=%v, want ok and nothing recorded", ok, got)
				}
				return
			}
			if ok || w.Code != http.StatusForbidden {
				t.Fatalf("ok=%v status=%d body=%s, want a 403", ok, w.Code, w.Body)
			}
			want := identityobs.Pair{Gate: identityobs.GateSelf, Reason: tc.reason}
			if len(got) != 1 || got[want] != 1 {
				t.Fatalf("series moved = %v, want exactly %v by 1 (and no gate=self_or_admin series)", got, want)
			}
		})
	}
}

// selfOrAdmin is unchanged: the same inputs, its own gate, the admin override.
func TestSelfOrAdmin_StaysAtGateSelfOrAdmin(t *testing.T) {
	for _, tc := range []selfGateCase{
		{"no header", "", false, identityobs.ReasonNoIdentity},
		{"a blank header", "   ", true, identityobs.ReasonNoIdentity},
		{"the right seat on another domain", "alice@evil.example", true, identityobs.ReasonNonCanonical},
		{"no @ at all", "alice", true, identityobs.ReasonNonCanonical},
		{"another canonical seat", "bob@ctf.local", true, identityobs.ReasonMismatch},
		{"an ADMIN_EMAILS identity on the seat domain (override)", selfGateAdmin, true, ""},
		{"an ADMIN_EMAILS identity on another domain (override)", selfGateStaff, true, ""},
		{"the seat itself", "alice@ctf.local", true, ""},
		{"the seat itself, upper case", "ALICE@CTF.LOCAL", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := selfGateCounts()
			w := httptest.NewRecorder()
			ok := selfGateHandler().selfOrAdmin(w, selfGateRequest(tc.email, tc.set), "alice")
			got := selfGateMoved(before)
			if tc.reason == "" {
				if !ok || len(got) != 0 {
					t.Fatalf("ok=%v, series moved=%v, want ok and nothing recorded", ok, got)
				}
				return
			}
			if ok || w.Code != http.StatusForbidden {
				t.Fatalf("ok=%v status=%d body=%s, want a 403", ok, w.Code, w.Body)
			}
			want := identityobs.Pair{Gate: identityobs.GateSelfOrAdmin, Reason: tc.reason}
			if len(got) != 1 || got[want] != 1 {
				t.Fatalf("series moved = %v, want exactly %v by 1 (and no gate=self series)", got, want)
			}
		})
	}
}

// An empty EXPECTED_EMAIL_DOMAIN refuses every identity at both gates as non_canonical.
func TestSelfGates_EmptyDomainIsNonCanonicalAtEachOwnGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate identityobs.Gate
		run  func(h *Handler, w http.ResponseWriter, r *http.Request) bool
	}{
		{"self", identityobs.GateSelf, func(h *Handler, w http.ResponseWriter, r *http.Request) bool { return h.selfOnly(w, r, "alice") }},
		{"self_or_admin", identityobs.GateSelfOrAdmin, func(h *Handler, w http.ResponseWriter, r *http.Request) bool { return h.selfOrAdmin(w, r, "alice") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := selfGateHandler()
			h.emailDomain = ""
			before := selfGateCounts()
			if tc.run(h, httptest.NewRecorder(), selfGateRequest("alice@ctf.local", true)) {
				t.Fatal("an identity passed with EXPECTED_EMAIL_DOMAIN empty")
			}
			want := identityobs.Pair{Gate: tc.gate, Reason: identityobs.ReasonNonCanonical}
			if got := selfGateMoved(before); len(got) != 1 || got[want] != 1 {
				t.Fatalf("series moved = %v, want exactly %v by 1", got, want)
			}
		})
	}
}

// judgeSelf is the one core: it normalises the header and says why, and records nothing.
func TestJudgeSelf_NormalisesAndClassifiesWithoutRecording(t *testing.T) {
	h := selfGateHandler()
	before := selfGateCounts()
	for _, tc := range []struct {
		email      string
		set        bool
		wantEmail  string
		wantReason identityobs.Reason
		wantOK     bool
	}{
		{"", false, "", identityobs.ReasonNoIdentity, false},
		{"  ", true, "", identityobs.ReasonNoIdentity, false},
		{" ALICE@CTF.LOCAL ", true, "alice@ctf.local", "", true},
		{"Bob@ctf.local", true, "bob@ctf.local", identityobs.ReasonMismatch, false},
		{"Alice@Evil.example", true, "alice@evil.example", identityobs.ReasonNonCanonical, false},
		{selfGateStaff, true, selfGateStaff, identityobs.ReasonNonCanonical, false}, // judgeSelf knows nothing of ADMIN_EMAILS
	} {
		email, reason, ok := h.judgeSelf(selfGateRequest(tc.email, tc.set), "alice")
		if email != tc.wantEmail || reason != tc.wantReason || ok != tc.wantOK {
			t.Errorf("judgeSelf(%q, set=%v) = (%q, %q, %v), want (%q, %q, %v)", tc.email, tc.set, email, reason, ok, tc.wantEmail, tc.wantReason, tc.wantOK)
		}
	}
	if got := selfGateMoved(before); len(got) != 0 {
		t.Fatalf("judgeSelf recorded %v: it must judge only", got)
	}
}

// --- source checks (the gate word of each function, and the one shared core) -------

// gateWordsIn lists the identityobs.Gate* selectors used inside the declaration named fn
// in src.
func gateWordsIn(t *testing.T, src, fn string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	seen := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "identityobs" && strings.HasPrefix(sel.Sel.Name, "Gate") {
					seen[sel.Sel.Name] = true
				}
			}
			return true
		})
	}
	var out []string
	for w := range seen {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// selfGateSourceProblems is the rule: selfOnly (answer.go) names GateSelf and no other
// gate, selfOrAdmin (api.go) names GateSelfOrAdmin and no other, and both reach the
// header only through judgeSelf (neither calls emailMatchesUser; judgeSelf is called from
// each).
func selfGateSourceProblems(t *testing.T, answerSrc, apiSrc string) []string {
	t.Helper()
	var out []string
	if got := strings.Join(gateWordsIn(t, answerSrc, "selfOnly"), ","); got != "GateSelf" {
		out = append(out, "selfOnly names gate word(s) ["+got+"], want exactly GateSelf")
	}
	if got := strings.Join(gateWordsIn(t, apiSrc, "selfOrAdmin"), ","); got != "GateSelfOrAdmin" {
		out = append(out, "selfOrAdmin names gate word(s) ["+got+"], want exactly GateSelfOrAdmin")
	}
	calls := func(src, name, fn string) int {
		n := 0
		for _, s := range callSites(t, src, name) {
			if s.fn == fn {
				n++
			}
		}
		return n
	}
	if calls(answerSrc, "judgeSelf", "selfOnly") != 1 {
		out = append(out, "selfOnly does not call judgeSelf exactly once")
	}
	if calls(apiSrc, "judgeSelf", "selfOrAdmin") != 1 {
		out = append(out, "selfOrAdmin does not call judgeSelf exactly once")
	}
	for _, fn := range []string{"selfOnly", "selfOrAdmin"} {
		if calls(answerSrc, "emailMatchesUser", fn)+calls(apiSrc, "emailMatchesUser", fn) != 0 {
			out = append(out, fn+" compares the identity itself (emailMatchesUser) instead of through judgeSelf")
		}
	}
	return out
}

func readSelfGateSources(t *testing.T) (answerSrc, apiSrc string) {
	t.Helper()
	a, err := os.ReadFile("answer.go")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(a), string(b)
}

func TestSelfGateSource_EachFunctionRecordsAtItsOwnGateThroughOneCore(t *testing.T) {
	answerSrc, apiSrc := readSelfGateSources(t)
	if p := selfGateSourceProblems(t, answerSrc, apiSrc); len(p) != 0 {
		t.Fatalf("the real source is flagged: %v", p)
	}

	// Not vacuous: each drift is flagged on a copy of the real source.
	for _, tc := range []struct {
		name     string
		inAPI    bool // the mutation is in api.go (selfOrAdmin), not answer.go (selfOnly)
		from, to string
	}{
		{"selfOnly put back on gate self_or_admin", false, "identityobs.GateSelf, reason", "identityobs.GateSelfOrAdmin, reason"},
		{"selfOrAdmin moved onto gate self", true, "identityobs.GateSelfOrAdmin, reason", "identityobs.GateSelf, reason"},
		{"selfOnly compares the identity itself", false, "h.judgeSelf(r, user)", "h.judgeSelf(r, user)\n\t_ = emailMatchesUser(email, user, h.emailDomain)"},
		{"selfOrAdmin compares the identity itself", true, "h.judgeSelf(r, user)", "h.judgeSelf(r, user)\n\t_ = emailMatchesUser(email, user, h.emailDomain)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := answerSrc, apiSrc
			target := &a
			if tc.inAPI {
				target = &b
			}
			if strings.Count(*target, tc.from) != 1 {
				t.Fatalf("the mutation text %q occurs %d times in the real source, want exactly 1 (the mutation is not testing anything)", tc.from, strings.Count(*target, tc.from))
			}
			*target = strings.Replace(*target, tc.from, tc.to, 1)
			if p := selfGateSourceProblems(t, a, b); len(p) == 0 {
				t.Fatal("the mutated source was not flagged")
			}
		})
	}
}
