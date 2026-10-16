package view

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// bidiNameSites pins app#343: every place a display name is drawn must sit in
// its own <bdi>, so a stray right-to-left character in one name (a character
// the server's Cc/Cf rule does not catch, e.g. an Arabic or Hebrew letter, or
// a bidi control that predates the rule and is already stored) cannot reorder
// the text next to it — the rank, the "—" before an author, the identity
// suffix. <bdi> isolates by default (unicode-bidi: isolate), so no CSS is
// needed. esc() is unchanged: <bdi> is markup around the escaped text, not a
// replacement for escaping.
//
// The minimum counts are the number of sites found when this was written; a
// new site that draws a name must be added here (or the test below fails on
// the unwrapped esc() call even without a count change).
//
// Sites: scoreboard (leaderboard row, activity, pod, challenge board, solver
// list), board (public list, thread header, message authors, admin list and
// header), Me (identity heading), admin dashboard (GET /).
var bidiNameSites = []struct {
	file string // path under templates/
	min  int    // display-name sites found when this was written
}{
	{"portal/pane-scoreboard.tmpl", 5},
	{"portal/pane-board.tmpl", 6},
	{"portal/pane-me.tmpl", 1},
	{"index.html", 5},
}

// displayNameEsc matches an esc() call whose argument is a display name field
// (the server's display_name / the board's authorDisplay) or the Me pane's
// displayName local. first_solver is a username slug, not a display name.
var displayNameEsc = regexp.MustCompile(`esc\((?:[a-z]+\.(?:display_name|authorDisplay)\b|displayName\))`)

func TestDisplayNames_AreBidiIsolated(t *testing.T) {
	for _, site := range bidiNameSites {
		b, err := os.ReadFile("templates/" + site.file)
		if err != nil {
			t.Fatalf("read %s: %v", site.file, err)
		}
		src := string(b)
		locs := displayNameEsc.FindAllStringIndex(src, -1)
		if len(locs) < site.min {
			t.Errorf("%s: found %d display-name esc() calls, want at least %d (did a site move?)", site.file, len(locs), site.min)
		}
		for _, loc := range locs {
			before := src[:loc[0]]
			// <bdi>${esc(...)} in a template literal, ...<bdi>' + esc(...) in a
			// string concatenation, <bdi> directly before it otherwise.
			if !strings.HasSuffix(before, "<bdi>${") && !strings.HasSuffix(before, "<bdi>' + ") && !strings.HasSuffix(before, "<bdi>") {
				line := strings.Count(before, "\n") + 1
				t.Errorf("%s:%d: %s is not wrapped in <bdi> (app#343)", site.file, line, src[loc[0]:loc[1]])
			}
		}
		if n := strings.Count(src, "<bdi>"); n < site.min {
			t.Errorf("%s: %d <bdi> elements, want at least %d", site.file, n, site.min)
		}
	}
}
