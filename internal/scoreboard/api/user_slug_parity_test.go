package api

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The username-slug expression is copied into scoring and ingest (neither can
// import api); one shared definition is app#440. Until then the three must be
// the same expression, extracted from the source (an extraction that finds
// nothing fails, it never passes).
func TestUserSlugExpressionIsTheSameInScoringAndIngest(t *testing.T) {
	re := regexp.MustCompile("var validUser = regexp\\.MustCompile\\(`([^`]+)`\\)")
	for _, rel := range []string{
		filepath.Join("..", "scoring", "scoring.go"),
		filepath.Join("..", "ingest", "ingest.go"),
	} {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(src)
		if m == nil {
			t.Fatalf("no `var validUser = regexp.MustCompile(...)` in %s: the extraction is broken", rel)
		}
		if got, want := string(m[1]), validUser.String(); got != want {
			t.Errorf("%s: validUser = %s, api.validUser = %s", rel, got, want)
		}
	}
}
