package harness

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
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
