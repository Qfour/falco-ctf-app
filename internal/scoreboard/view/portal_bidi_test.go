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
// (name -> body) and the dashboard source.
func checkBidiNames(portal map[string]string, index string) []error {
	var errs []error
	files := map[string]string{"index.html": index}
	for n, b := range portal {
		files[n] = b
	}
	sites, portalDecls, indexDecls := 0, 0, 0
	for name, raw := range files {
		body := stripEscComments(raw)
		for _, m := range bareNameEscRe.FindAllString(body, -1) {
			errs = append(errs, fmt.Errorf("%s: %q hands a display name to a bare esc(); use nameHTML() so the name is bidi-isolated (app#343)", name, strings.TrimSpace(m)))
		}
		n := len(nameHTMLUseRe.FindAllString(body, -1))
		sites += n
		if floor, ok := bidiFloors[name]; ok && n < floor {
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
	for _, err := range checkBidiNames(portal, index) {
		t.Error(err)
	}
}

// TestDisplayNames_BidiGateCatchesRegressions pins that the gate goes red for
// the edits that would undo the isolation, by applying each to the real source.
func TestDisplayNames_BidiGateCatchesRegressions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(portal map[string]string, index *string)
	}{
		{"one nameHTML goes back to a bare esc", func(p map[string]string, _ *string) {
			p["pane-scoreboard.tmpl"] = strings.Replace(p["pane-scoreboard.tmpl"], "nameHTML(p.display_name || p.user)", "esc(p.display_name || p.user)", 1)
		}},
		{"a new partial escapes display_name bare", func(p map[string]string, _ *string) {
			p["pane-new.tmpl"] = "<script>el.innerHTML = esc(row.display_name);</script>"
		}},
		{"a new partial escapes authorDisplay bare", func(p map[string]string, _ *string) {
			p["pane-new.tmpl"] = "<script>el.innerHTML = `${esc(m.authorDisplay || m.author)}`;</script>"
		}},
		{"the Me pane escapes displayName bare", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] = strings.Replace(p["pane-me.tmpl"], "nameHTML(displayName)", "esc(displayName)", 1)
		}},
		{"a second nameHTML declaration", func(p map[string]string, _ *string) {
			p["pane-new.tmpl"] = "<script>const nameHTML = (s) => esc(s);</script>"
		}},
		{"the nameHTML declaration is gone", func(p map[string]string, _ *string) {
			p["core-util.tmpl"] = strings.Replace(p["core-util.tmpl"], nameHTMLWantLine, "", 1)
		}},
		{"nameHTML stops using <bdi>", func(p map[string]string, _ *string) {
			p["core-util.tmpl"] = strings.Replace(p["core-util.tmpl"], nameHTMLWantLine, `const nameHTML = (s) => esc(s);`, 1)
		}},
		{"the dashboard escapes a name bare", func(_ map[string]string, idx *string) {
			*idx = strings.Replace(*idx, "nameHTML(s.display_name || s.user)", "esc(s.display_name || s.user)", 1)
		}},
		{"the dashboard loses its nameHTML", func(_ map[string]string, idx *string) {
			*idx = strings.Replace(*idx, nameHTMLWantLine, "", 1)
		}},
		{"every site is gone", func(p map[string]string, idx *string) {
			for k := range p {
				p[k] = ""
			}
			*idx = ""
		}},
	}
	basePortal, baseIndex := bidiSources(t)
	if errs := checkBidiNames(basePortal, baseIndex); len(errs) != 0 {
		t.Fatalf("the unmodified source must pass the gate first: %v", errs)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			portal := map[string]string{}
			for k, v := range basePortal {
				portal[k] = v
			}
			index := baseIndex
			c.mutate(portal, &index)
			if len(checkBidiNames(portal, index)) == 0 {
				t.Errorf("the gate stayed green after: %s", c.name)
			}
		})
	}
}
