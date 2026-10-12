//go:build e2e

package e2e

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// scenarioLimit bounds one whole scenario. It is the time a hung run takes to
// fail, not a duration any step waits for.
const scenarioLimit = 4 * time.Minute

// Env is one scenario's world: a fresh scoreboard child (own binary instance,
// own SQLite file), the recording proxy in front of it, the ttyd stub, the
// seeded state, and a browser (ADR-0031 D3: nothing is shared between
// scenarios, and they run one after another).
type Env struct {
	T      *testing.T
	Ctx    context.Context
	Root   string
	User   string
	Child  *harness.Scoreboard
	Proxy  *harness.Proxy
	Stub   *harness.TLSStub
	Seeder *harness.Seeder
	B      *Browser
}

// NewEnv starts the world and applies the named seed for user1. The binary comes
// from E2E_SCOREBOARD_BIN (built by Dockerfile.e2e like scoreboard/Dockerfile);
// without it the run fails — it never builds a substitute or skips.
func NewEnv(t *testing.T, seed string) *Env {
	t.Helper()
	bin := os.Getenv("E2E_SCOREBOARD_BIN")
	if bin == "" {
		t.Fatal(errNoBinary)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := harness.RepoRoot(wd)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), scenarioLimit)
	t.Cleanup(cancel)

	const user = "user1"
	email, err := harness.EmailFor(user)
	if err != nil {
		t.Fatal(err)
	}
	challenges := filepath.Join(root, "challenges")
	scenario := filepath.Join(root, "scenarios", "nimbusbreach-full", "scenario.yaml")
	plan, err := harness.LoadPlan(challenges, scenario)
	if err != nil {
		t.Fatal(err)
	}

	// The proxy's address must be known before the child starts: it is the one
	// origin the child's origin guard accepts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://" + ln.Addr().String()

	stub, err := harness.NewTLSStub(user + "." + harness.TtydSuffix)
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(stub.Close)

	child, err := harness.StartScoreboard(ctx, harness.ScoreboardConfig{
		Binary: bin, WorkDir: t.TempDir(),
		ChallengesDir: challenges, ScenarioFile: scenario,
		AllowedOrigin: origin, TtydSuffix: harness.TtydSuffix,
	})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("scoreboard child log:\n%s", child.Logs())
		}
		child.Close()
	})

	proxy, err := harness.NewProxy(ln, child, email)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)

	seeder := harness.NewSeeder(child, email, plan)
	if err := seeder.Seed(ctx, seed, user); err != nil {
		t.Fatalf("seed %s: %v", seed, err)
	}

	b := NewBrowser(t, BrowserConfig{
		Proxy:        proxy,
		ExtraOrigins: []string{stub.Origin()},
		HostRules:    harness.HostResolverRules(map[string]string{stub.Host(): stub.Addr()}),
		SPKIHash:     stub.SPKIHash(),
	})
	return &Env{T: t, Ctx: ctx, Root: root, User: user, Child: child, Proxy: proxy, Stub: stub, Seeder: seeder, B: b}
}

// Detail reads the user's journey over HTTP (not through the proxy, so it is
// not in the request log) and returns its "detail" object.
func (e *Env) Detail(mission string) map[string]any {
	e.T.Helper()
	j, err := e.Seeder.Journey(e.Ctx, e.User, mission)
	if err != nil {
		e.T.Fatalf("journey: %v", err)
	}
	d, _ := j["detail"].(map[string]any)
	if d == nil {
		e.T.Fatalf("journey has no detail: %v", j)
	}
	return d
}
