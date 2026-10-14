package harness

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildScoreboard builds cmd/scoreboard (CGO off, like scoreboard/Dockerfile).
// It leaves out the Dockerfile's -trimpath and -ldflags="-s -w": they change
// only file paths and symbols in the binary, not what it does, and -trimpath
// would miss the build cache that `go vet ./...` has just filled in
// Dockerfile.test — a full recompile (modernc.org/sqlite above all) that made
// this test the critical path of the required `test` check (~20 s locally,
// 30-55 s on the CI runner; with the cache, ~1 s: review-5x T3 R5#1). The
// browser E2E (Dockerfile.e2e) runs the binary built with the Dockerfile's
// flags. A missing toolchain is a failure, not a skip.
func buildScoreboard(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "scoreboard")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/scoreboard")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/scoreboard: %v\n%s", err, b)
	}
	return out
}

func getJSON(t *testing.T, method, url string, hdr map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header
}

// TestRealBinary_BehindTheProxy runs the whole non-browser chain on the real
// cmd/scoreboard binary, so `make test` covers it without Chromium: the env
// allowlist, the seeds over HTTP (each in its production caller's shape), the
// proxy's identity injection, the CSP that reaches the client untouched, and
// the child's own origin guard (ALLOWED_ORIGINS): accepted for the proxy's
// origin, refused for a foreign one and for none — the refusals asked of the
// child directly, since the proxy turns a foreign Origin away before the child
// ever sees it.
func TestRealBinary_BehindTheProxy(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	bin := buildScoreboard(t, root)
	plan, err := LoadPlan(filepath.Join(root, "challenges"), filepath.Join(root, "scenarios", "nimbusbreach-full", "scenario.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://" + ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	child, err := StartScoreboard(ctx, ScoreboardConfig{
		Binary: bin, WorkDir: t.TempDir(),
		ChallengesDir: filepath.Join(root, "challenges"),
		ScenarioFile:  filepath.Join(root, "scenarios", "nimbusbreach-full", "scenario.yaml"),
		AllowedOrigin: origin, TtydSuffix: TtydSuffix,
	})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(child.Close)
	proxy, err := NewProxy(ln, child, "user1@"+IdentityDomain)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)

	// Seeds, each for its own user. The expected current mission is part of
	// the seed's own check; here the journey is read back through the proxy.
	for user, seed := range map[string]string{"user1": SeedDirty05, "user2": SeedClean05, "user3": SeedFresh} {
		if err := NewSeeder(child, user+"@"+IdentityDomain, plan).Seed(ctx, seed, user); err != nil {
			t.Fatalf("seed %s for %s: %v", seed, user, err)
		}
	}
	if len(proxy.Entries()) != 0 {
		t.Fatalf("seeding must not pass through the proxy, but it logged:\n%s", FormatLog(proxy.Entries()))
	}

	code, j, _ := getJSON(t, "GET", origin+"/api/users/user1/journey", nil)
	detail, _ := j["detail"].(map[string]any)
	if code != 200 || j["current"] != "05-silent-search" || detail["dirty"] != true {
		t.Fatalf("user1 through the proxy: %d current=%v dirty=%v (identity not injected, or the dirty seed did not hold)", code, j["current"], detail["dirty"])
	}
	// The identity is the proxy's, not the client's: asking for user1's journey
	// while claiming to be someone else changes nothing.
	code, _, _ = getJSON(t, "GET", origin+"/api/users/user1/journey", map[string]string{IdentityHeader: "user9@" + IdentityDomain})
	if code != 200 {
		t.Errorf("a client-supplied identity header must be overwritten, got %d", code)
	}
	// ...and without the proxy the same read is refused: the child has no
	// identity of its own.
	if code, _, _ = getJSON(t, "GET", child.URL()+"/api/users/user1/journey", nil); code != 403 {
		t.Errorf("the child read without an identity header answered %d, want 403", code)
	}

	// The portal page reaches the client with the child's own CSP.
	_, _, h := getJSON(t, "GET", origin+"/portal", nil)
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src https://*."+TtydSuffix) || !strings.Contains(csp, "'nonce-") {
		t.Errorf("portal CSP = %q: want the nonce and frame-src from PORTAL_TTYD_SUFFIX", csp)
	}

	// Origin guard. Through the proxy a foreign Origin never reaches the child:
	// the proxy answers 403 itself (refused-origin) and forwards nothing, so
	// that 403 is the proxy's and says nothing about the child's guard.
	const resetPath = "/api/users/user1/challenges/05-silent-search/reset-dirty"
	mark := proxy.Mark()
	if code, _, _ = getJSON(t, "POST", origin+resetPath, map[string]string{"Origin": "https://evil.test"}); code != 403 {
		t.Errorf("reset-dirty with a foreign Origin through the proxy answered %d, want 403", code)
	}
	if got := proxy.Since(mark); len(got) != 1 || got[0].Fault != "refused-origin" {
		t.Errorf("the proxy should have refused the foreign Origin itself (refused-origin), log:\n%s", FormatLog(got))
	}
	// The child's guard, asked directly with the identity the proxy would have
	// injected: a foreign Origin is refused, and so is a request with no
	// Origin or Referer at all (fail-closed: what curl or a server sends).
	user1 := map[string]string{IdentityHeader: "user1@" + IdentityDomain}
	for name, hdr := range map[string]map[string]string{
		"a foreign Origin":     {IdentityHeader: user1[IdentityHeader], "Origin": "https://evil.test"},
		"no Origin or Referer": user1,
	} {
		if code, body, _ := getJSON(t, "POST", child.URL()+resetPath, hdr); code != 403 {
			t.Errorf("the child's origin guard let reset-dirty with %s through: %d %v (ALLOWED_ORIGINS=%s)", name, code, body, origin)
		}
	}
	_, j, _ = getJSON(t, "GET", child.URL()+"/api/users/user1/journey", user1)
	if d, _ := j["detail"].(map[string]any); d["dirty"] != true {
		t.Fatalf("a refused reset-dirty changed the server state: dirty=%v (want true)", d["dirty"])
	}
	// The proxy's own origin is the allowed one: forwarded, accepted, clean.
	if code, _, _ = getJSON(t, "POST", origin+resetPath, map[string]string{"Origin": origin}); code != 200 {
		t.Errorf("reset-dirty with the allowed Origin answered %d, want 200", code)
	}
	// The log has both POSTs: the refused one (with its fault, nothing
	// forwarded) and the accepted one (forwarded, 200).
	wantWrites := []string{"POST " + resetPath, "POST " + resetPath}
	if got := proxy.Writes(mark); strings.Join(got, "|") != strings.Join(wantWrites, "|") {
		t.Errorf("writes = %v, want the refused and the accepted reset-dirty POST", got)
	}
	if got := proxy.Since(mark); len(got) != 2 || got[1].Fault != "" || got[1].Status != 200 {
		t.Errorf("the allowed reset-dirty should have been forwarded and answered 200, log:\n%s", FormatLog(got))
	}
	_, j, _ = getJSON(t, "GET", origin+"/api/users/user1/journey", nil)
	if d, _ := j["detail"].(map[string]any); d["dirty"] != false {
		t.Errorf("after the allowed reset the attempt should be clean, detail=%v", d)
	}
	// The child's log is the diagnostic a failure would print.
	if !strings.Contains(child.Logs(), `"msg":"listening"`) {
		t.Errorf("child log has no listening line:\n%s", child.Logs())
	}
	child.Close()
	select {
	case <-child.Done():
	default:
		t.Error("Close returned but the child is still running")
	}
}

func TestStartScoreboard_RefusesAPlantedEnvAndAMissingBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := StartScoreboard(ctx, ScoreboardConfig{Binary: "/nonexistent/scoreboard"}); err == nil {
		t.Error("StartScoreboard started a missing binary")
	}
	if _, err := StartScoreboard(ctx, ScoreboardConfig{}); err == nil {
		t.Error("StartScoreboard accepted an empty config")
	}
	// A config whose pieces would not pass CheckChildEnv fails before exec.
	bin := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := StartScoreboard(ctx, ScoreboardConfig{
		Binary: bin, WorkDir: t.TempDir(), ChallengesDir: "/c", ScenarioFile: "/s",
		AllowedOrigin: "http://127.0.0.1:1", TtydSuffix: "ctf-event.dev",
	})
	if err == nil || !strings.Contains(err.Error(), ".test") {
		t.Errorf("a real-looking ttyd suffix should be refused before exec, got %v", err)
	}
}
