package harness

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// UserPattern must stay the same expression as validUser in the scoreboard's
// api package, or `make e2e-serve AS=` could accept a name the server rejects
// (or the reverse).
func TestUserPattern_MatchesTheScoreboardsValidUser(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, "internal", "scoreboard", "api", "api.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("var validUser = regexp\\.MustCompile\\(`([^`]+)`\\)").FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find `var validUser = regexp.MustCompile(...)` in internal/scoreboard/api/api.go — extraction is broken")
	}
	if got, want := UserPattern.String(), string(m[1]); got != want {
		t.Errorf("harness.UserPattern = %s, but api.validUser = %s", got, want)
	}
}

func TestEmailFor(t *testing.T) {
	good := map[string]string{"user1": "user1@e2e.test", "a": "a@e2e.test", "u-2": "u-2@e2e.test"}
	for user, want := range good {
		if got, err := EmailFor(user); err != nil || got != want {
			t.Errorf("EmailFor(%q) = %q, %v; want %q", user, got, err, want)
		}
	}
	// AS= reaches an identity header and a docker command line: nothing that
	// could carry a separator, a quote, a header break or a second address.
	for _, bad := range []string{"", "User1", "-x", "a b", "a@b", "a\r\nX: 1", "a;b", "a'b", "a$(x)", "a/b", "../x"} {
		if got, err := EmailFor(bad); err == nil {
			t.Errorf("EmailFor(%q) = %q, want an error", bad, got)
		}
	}
}

func TestSeedNames(t *testing.T) {
	got := SeedNames()
	want := []string{SeedClean05, SeedDirty05, SeedFresh}
	if len(got) != len(want) {
		t.Fatalf("SeedNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SeedNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// seenRequest is what the recording Site keeps of one request.
type seenRequest struct {
	method, path string
	header       http.Header
	body         []byte
}

// authRequestHeaders lists the X-Auth-Request-* names a request carried
// (matched on the canonical key, as app#334's HasProxyIdentityHeader does).
func authRequestHeaders(h http.Header) []string {
	var out []string
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Auth-Request-") {
			out = append(out, k)
		}
	}
	return out
}

func isJSON(h http.Header) bool {
	mt, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// Each seed request must have the shape its production caller gives it
// (ADR-0031 D3, review-5x T3 R2#1 / R4#2). The webhook and the submit carry no
// X-Auth-Request-* header — the scoreboard refuses that header on
// /falco/events as the browser path (app#334), so a seeder that sends it on
// every request turns the required `make test` red the day #334 lands — and
// the self-scope read carries exactly the identity the scoreboard asks for.
func TestSeeder_EachRequestHasItsProductionCallersShape(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []seenRequest
	)
	site, err := NewSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, seenRequest{r.Method, r.URL.Path, r.Header.Clone(), b})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/falco/events":
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.HasSuffix(r.URL.Path, "/submit"):
			_, _ = w.Write([]byte(`{"solved":true}`))
		default:
			_, _ = w.Write([]byte(`{"current":"05-silent-search"}`))
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const email = "user1@" + IdentityDomain
	s := NewSeeder(site, email, &Plan{})
	if err := s.FireRule(ctx, "user1", "Some Rule"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(ctx, "user1", "05-silent-search", "FALCO{dev-x}"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Journey(ctx, "user1", ""); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("the site saw %d requests, want 3", len(seen))
	}
	webhook, submit, read := seen[0], seen[1], seen[2]

	if webhook.method != http.MethodPost || webhook.path != "/falco/events" {
		t.Fatalf("FireRule sent %s %s", webhook.method, webhook.path)
	}
	if h := authRequestHeaders(webhook.header); len(h) != 0 {
		t.Errorf("FireRule sent %v: falcosidekick sends no X-Auth-Request-* header, and the scoreboard refuses one on the webhook (app#334)", h)
	}
	if !isJSON(webhook.header) {
		t.Errorf("FireRule Content-Type = %q, want application/json", webhook.header.Get("Content-Type"))
	}
	var ev struct {
		Rule         string         `json:"rule"`
		OutputFields map[string]any `json:"output_fields"`
	}
	if err := json.Unmarshal(webhook.body, &ev); err != nil || ev.Rule != "Some Rule" || ev.OutputFields["k8s.ns.name"] != "ctf-user1" {
		t.Errorf("FireRule body = %s (%v)", webhook.body, err)
	}

	if submit.method != http.MethodPost || submit.path != "/api/challenges/05-silent-search/submit" {
		t.Fatalf("Submit sent %s %s", submit.method, submit.path)
	}
	if h := authRequestHeaders(submit.header); len(h) != 0 {
		t.Errorf("Submit sent %v: the collector forward (the submit's primary path) carries no X-Auth-Request-* header", h)
	}
	if !isJSON(submit.header) {
		t.Errorf("Submit Content-Type = %q, want application/json", submit.header.Get("Content-Type"))
	}

	if read.method != http.MethodGet || read.path != "/api/users/user1/journey" {
		t.Fatalf("Journey sent %s %s", read.method, read.path)
	}
	if got := read.header.Get(IdentityHeader); got != email {
		t.Errorf("Journey %s = %q, want %q (the read gate refuses a read without it)", IdentityHeader, got, email)
	}
	if h := authRequestHeaders(read.header); len(h) != 1 {
		t.Errorf("Journey sent X-Auth-Request-* headers %v, want exactly %s", h, IdentityHeader)
	}
}
