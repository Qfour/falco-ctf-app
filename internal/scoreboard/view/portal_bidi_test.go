package view

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// app#343: a participant-chosen name (display_name, the board's authorDisplay,
// the Me pane's displayName) is put into markup ONLY through nameHTML(), which
// is esc() inside a <bdi>. <bdi> isolates the name's text direction
// (unicode-bidi: isolate), so a right-to-left character in one name (a letter
// the server's Cc/Cf rule does not reject, or a bidi control stored before
// that rule) cannot reorder the text next to it: the rank, the "—" before an
// author, the identity suffix. esc() itself is unchanged.
//
// The gate SCANS: every partial of the portal and the admin dashboard
// (index.html) is read, so a partial or a call site added later is covered
// without anyone editing a list here. It rejects a name field handed to a bare
// esc(); it does not enumerate the sites. The per-file counts below are only a
// FLOOR, so a site that silently stops matching the scan cannot make the gate
// pass on nothing.

// nameFieldArg is what makes an esc()/nameHTML() argument "a display name":
// x.display_name, x.authorDisplay, or the bare local displayName. A name
// reached under another spelling (an alias const) is not seen; the floor and
// the review are what cover that. first_solver is a username slug, not a name.
const nameFieldArg = `(?:[A-Za-z_$][\w$]*\.(?:display_name|authorDisplay)\b|displayName\b)`

var (
	bareNameEscRe  = regexp.MustCompile(`(?:^|[^\w$.])esc\(\s*` + nameFieldArg)
	nameHTMLUseRe  = regexp.MustCompile(`(?:^|[^\w$.])nameHTML\(\s*` + nameFieldArg)
	nameHTMLDeclRe = regexp.MustCompile(`\b(?:function\*?|const|let|var|class)\s+nameHTML\b`)
	// esc(nameHTML(x)) shows the literal text "&lt;bdi&gt;"; nameHTML(esc(x))
	// escapes twice ("&amp;lt;"). Neither is an XSS, both are a broken display.
	doubleEscRe = regexp.MustCompile(`(?:^|[^\w$.])(?:esc\(\s*nameHTML\(|nameHTML\(\s*esc\()`)
)

// The two pinned declarations. The portal's lives in core-util.tmpl after esc
// (TDZ); the dashboard has its own esc, so its own copy next to it.
const nameHTMLWantLine = `const nameHTML = (s) => '<bdi>' + esc(s) + '</bdi>';`

// bidiFloors are the numbers of nameHTML(<name field>) sites when this was
// written: scoreboard 5 (leaderboard row, activity, pod, challenge board,
// solver list), board 6 (public list, thread header, message authors, admin
// list and header), Me 1, admin dashboard 5.
var bidiFloors = map[string]int{
	"pane-scoreboard.tmpl": 5,
	"pane-board.tmpl":      6,
	"pane-me.tmpl":         1,
	"index.html":           5,
}

// checkBidiNames returns every violation of the rule in the portal partials
// (name -> body) and the dashboard source. floors is the per-file lower bound
// on nameHTML(<name>) sites; a file named in floors that is not among the
// scanned files is an error too (a renamed or split partial must not drop out
// of the floor silently).
func checkBidiNames(portal map[string]string, index string, floors map[string]int) []error {
	var errs []error
	files := map[string]string{"index.html": index}
	for n, b := range portal {
		files[n] = b
	}
	for name := range floors {
		if _, ok := files[name]; !ok {
			errs = append(errs, fmt.Errorf("%s has a nameHTML floor but is not among the scanned files (renamed or removed? move the floor with it)", name))
		}
	}
	sites, portalDecls, indexDecls := 0, 0, 0
	for name, raw := range files {
		body := stripEscComments(raw)
		for _, m := range bareNameEscRe.FindAllString(body, -1) {
			errs = append(errs, fmt.Errorf("%s: %q hands a display name to a bare esc(); use nameHTML() so the name is bidi-isolated (app#343)", name, strings.TrimSpace(m)))
		}
		for _, m := range doubleEscRe.FindAllString(body, -1) {
			errs = append(errs, fmt.Errorf("%s: %q escapes a name twice (nameHTML already calls esc)", name, strings.TrimSpace(m)))
		}
		n := len(nameHTMLUseRe.FindAllString(body, -1))
		sites += n
		if floor, ok := floors[name]; ok && n < floor {
			errs = append(errs, fmt.Errorf("%s: %d nameHTML(<name>) sites, want at least %d (a site moved or stopped matching the scan)", name, n, floor))
		}
		d := len(nameHTMLDeclRe.FindAllString(body, -1))
		if name == "index.html" {
			indexDecls += d
		} else {
			portalDecls += d
		}
		if d > 0 && !strings.Contains(body, nameHTMLWantLine) {
			errs = append(errs, fmt.Errorf("%s declares nameHTML, but not as the pinned line %q", name, nameHTMLWantLine))
		}
	}
	if sites == 0 {
		errs = append(errs, fmt.Errorf("the scan found no nameHTML(<name>) site at all: the gate would pass on nothing"))
	}
	if portalDecls != 1 {
		errs = append(errs, fmt.Errorf("the portal declares nameHTML %d times, want exactly 1 (core-util.tmpl)", portalDecls))
	}
	if indexDecls != 1 {
		errs = append(errs, fmt.Errorf("index.html declares nameHTML %d times, want exactly 1", indexDecls))
	}
	return errs
}

func bidiSources(t *testing.T) (map[string]string, string) {
	t.Helper()
	portal := map[string]string{}
	for _, p := range portalPartials(t) {
		portal[p.name] = p.body
	}
	return portal, indexHTML
}

func TestDisplayNames_AreBidiIsolated(t *testing.T) {
	portal, index := bidiSources(t)
	for _, err := range checkBidiNames(portal, index, bidiFloors) {
		t.Error(err)
	}
}

// TestDisplayNames_BidiGateCatchesRegressions pins that the gate goes red for
// the edits that would undo the isolation, by applying each to the real source.
// Each case names the error it must produce (want); with only set, EVERY error
// must be that one, so a case proves its own assert and not a neighbour's. The
// floor and the zero-sites asserts each have such a case: without it, deleting
// either assert would leave this table green.
func TestDisplayNames_BidiGateCatchesRegressions(t *testing.T) {
	type bidiSrc struct {
		portal map[string]string
		index  string
		floors map[string]int
	}
	cases := []struct {
		name   string
		want   string // a substring of at least one error
		only   bool   // every error contains want
		mutate func(s *bidiSrc)
	}{
		{"one nameHTML goes back to a bare esc", "hands a display name to a bare esc()", false, func(s *bidiSrc) {
			s.portal["pane-scoreboard.tmpl"] = strings.Replace(s.portal["pane-scoreboard.tmpl"], "nameHTML(p.display_name || p.user)", "esc(p.display_name || p.user)", 1)
		}},
		{"a new partial escapes display_name bare", "hands a display name to a bare esc()", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = esc(row.display_name);</script>"
		}},
		{"a new partial escapes authorDisplay bare", "hands a display name to a bare esc()", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = `${esc(m.authorDisplay || m.author)}`;</script>"
		}},
		{"the Me pane escapes displayName bare", "hands a display name to a bare esc()", false, func(s *bidiSrc) {
			s.portal["pane-me.tmpl"] = strings.Replace(s.portal["pane-me.tmpl"], "nameHTML(displayName)", "esc(displayName)", 1)
		}},
		{"a name is escaped around nameHTML", "escapes a name twice", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = esc(nameHTML(row.display_name));</script>"
		}},
		{"a name is escaped inside nameHTML", "escapes a name twice", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = nameHTML(esc(row.display_name));</script>"
		}},
		{"a second nameHTML declaration", "declares nameHTML 2 times", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>const nameHTML = (s) => esc(s);</script>"
		}},
		{"the nameHTML declaration is gone", "declares nameHTML 0 times", false, func(s *bidiSrc) {
			s.portal["core-util.tmpl"] = strings.Replace(s.portal["core-util.tmpl"], nameHTMLWantLine, "", 1)
		}},
		{"nameHTML stops using <bdi>", "not as the pinned line", true, func(s *bidiSrc) {
			s.portal["core-util.tmpl"] = strings.Replace(s.portal["core-util.tmpl"], nameHTMLWantLine, `const nameHTML = (s) => esc(s);`, 1)
		}},
		{"the dashboard escapes a name bare", "hands a display name to a bare esc()", false, func(s *bidiSrc) {
			s.index = strings.Replace(s.index, "nameHTML(s.display_name || s.user)", "esc(s.display_name || s.user)", 1)
		}},
		{"the dashboard loses its nameHTML", "index.html declares nameHTML 0 times", false, func(s *bidiSrc) {
			s.index = strings.Replace(s.index, nameHTMLWantLine, "", 1)
		}},
		// The floor, alone: the name is reached through an alias, which the scan
		// cannot see, so only the lower bound notices that a site is missing.
		{"a site is hidden behind an alias (floor only)", "want at least 5", true, func(s *bidiSrc) {
			s.portal["pane-scoreboard.tmpl"] = strings.Replace(s.portal["pane-scoreboard.tmpl"], "nameHTML(p.display_name || p.user)", "esc(nm)", 1)
		}},
		// F-1: the partial with a floor is renamed (and its site aliased), so the
		// floor's key matches no scanned file.
		{"a partial with a floor is renamed (floor key unmatched)", "has a nameHTML floor but is not among the scanned files", true, func(s *bidiSrc) {
			s.portal["pane-profile.tmpl"] = strings.Replace(s.portal["pane-me.tmpl"], "nameHTML(displayName)", "esc(nm)", 1)
			delete(s.portal, "pane-me.tmpl")
		}},
		{"every site is gone", "no nameHTML(<name>) site at all", false, func(s *bidiSrc) {
			for k := range s.portal {
				s.portal[k] = ""
			}
			s.index = ""
		}},
		// The zero-sites assert, alone: nothing but the two pinned declarations,
		// and no floors, so the only thing wrong is that nothing is checked.
		{"nothing is scanned (zero sites only)", "no nameHTML(<name>) site at all", true, func(s *bidiSrc) {
			s.portal = map[string]string{"core-util.tmpl": nameHTMLWantLine + "\n"}
			s.index = "  " + nameHTMLWantLine + "\n"
			s.floors = nil
		}},
	}
	basePortal, baseIndex := bidiSources(t)
	if errs := checkBidiNames(basePortal, baseIndex, bidiFloors); len(errs) != 0 {
		t.Fatalf("the unmodified source must pass the gate first: %v", errs)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := bidiSrc{portal: map[string]string{}, index: baseIndex, floors: bidiFloors}
			for k, v := range basePortal {
				src.portal[k] = v
			}
			c.mutate(&src)
			errs := checkBidiNames(src.portal, src.index, src.floors)
			if len(errs) == 0 {
				t.Fatalf("the gate stayed green after: %s", c.name)
			}
			found := false
			for _, err := range errs {
				if strings.Contains(err.Error(), c.want) {
					found = true
				} else if c.only {
					t.Errorf("unexpected error (this case must produce only %q): %v", c.want, err)
				}
			}
			if !found {
				t.Errorf("no error contains %q; got %v", c.want, errs)
			}
		})
	}
}
