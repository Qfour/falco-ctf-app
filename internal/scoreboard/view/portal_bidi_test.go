package view

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// app#343, app#377: text a participant WROTE and the portal puts INLINE next to
// other text (display_name, the board's authorDisplay, the Me pane's displayName,
// and a board thread's subject) is put into markup ONLY through nameHTML() (a
// name) or textHTML() (the subject), which are esc() inside a <bdi>. <bdi>
// isolates the text's direction (unicode-bidi: isolate), so a right-to-left
// character in one value (a letter the server's Cc/Cf rule does not reject, or a
// bidi control stored before that rule) cannot reorder the text next to it: the
// rank, the "—" before an author, the identity suffix. esc() itself is unchanged.
// A message body is a block of its own (a <div>), so it is not in this set.
//
// The gate SCANS: every partial of the portal and the admin dashboard
// (index.html) is read, so a partial or a call site added later is covered
// without anyone editing a list here. It rejects such a field handed to a bare
// esc(); it does not enumerate the sites. The per-file counts below are only a
// FLOOR, so a site that silently stops matching the scan cannot make the gate
// pass on nothing.

// inlineTextFields is THE definition of "participant inline text": the object
// fields whose value a participant wrote. The scan regexps below are derived from
// it, so a field added here is gated everywhere (and one removed is not). A name
// reached under another spelling (an alias const) is not seen; the floor and the
// review are what cover that. first_solver (app#428) is a username the server now
// holds to the slug grammar, but it is still a stored claimed value, so it is gated too.
var inlineTextFields = []string{"display_name", "authorDisplay", "subject", "first_solver"}

// inlineTextLocals are bare local names that hold such a value (the Me pane's
// `displayName`).
var inlineTextLocals = []string{"displayName"}

// inlineTextArg makes an esc()/nameHTML()/textHTML() argument "participant
// inline text": x.<field> for a field above, or a bare local above.
var inlineTextArg = `(?:[A-Za-z_$][\w$]*\.(?:` + strings.Join(inlineTextFields, "|") + `)\b|(?:` + strings.Join(inlineTextLocals, "|") + `)\b)`

var (
	bareEscRe = regexp.MustCompile(`(?:^|[^\w$.])esc\(\s*` + inlineTextArg)
	// A site: an isolating helper called on participant inline text.
	isolatedUseRe = regexp.MustCompile(`(?:^|[^\w$.])(?:nameHTML|textHTML)\(\s*` + inlineTextArg)
	// esc(nameHTML(x)) shows the literal text "&lt;bdi&gt;"; nameHTML(esc(x))
	// escapes twice ("&amp;lt;"). Neither is an XSS, both are a broken display.
	doubleEscRe = regexp.MustCompile(`(?:^|[^\w$.])(?:esc\(\s*(?:nameHTML|textHTML)\(|(?:nameHTML|textHTML)\(\s*esc\()`)
)

// bidiFloors are the numbers of isolated sites (nameHTML / textHTML on participant
// inline text) when this was written: scoreboard 6 (leaderboard row, activity, pod,
// challenge board, solver list, first_solver of a mission card), board 11 (6 names:
// public list, thread header, message authors, admin list and header; 5 subjects: my
// list, public list, thread header, admin list and header), Me 1, admin dashboard 6
// (5 + the mission card's first_solver).
var bidiFloors = map[string]int{
	"pane-scoreboard.tmpl": 6,
	"pane-board.tmpl":      11,
	"pane-me.tmpl":         1,
	"index.html":           6,
}

// checkBidiNames returns every violation of the rule in the portal partials
// (name -> body) and the dashboard source. floors is the per-file lower bound
// on isolated sites; a file named in floors that is not among the scanned files
// is an error too (a renamed or split partial must not drop out of the floor
// silently).
func checkBidiNames(portal map[string]string, index string, floors map[string]int) []error {
	var errs []error
	files, _ := scannedSources(portal, index)
	for name := range floors {
		if _, ok := files[name]; !ok {
			errs = append(errs, fmt.Errorf("%s has a nameHTML/textHTML floor but is not among the scanned files (renamed or removed? move the floor with it)", name))
		}
	}
	sites := 0
	for name, raw := range files {
		body := stripEscComments(raw)
		for _, m := range bareEscRe.FindAllString(body, -1) {
			errs = append(errs, fmt.Errorf("%s: %q hands participant inline text (display name / subject) to a bare esc(); use nameHTML() / textHTML() so it is bidi-isolated (app#343, app#377)", name, strings.TrimSpace(m)))
		}
		for _, m := range doubleEscRe.FindAllString(body, -1) {
			errs = append(errs, fmt.Errorf("%s: %q escapes a value twice (nameHTML / textHTML already call esc)", name, strings.TrimSpace(m)))
		}
		n := len(isolatedUseRe.FindAllString(body, -1))
		sites += n
		if floor, ok := floors[name]; ok && n < floor {
			errs = append(errs, fmt.Errorf("%s: %d nameHTML/textHTML(<participant inline text>) sites, want at least %d (a site moved or stopped matching the scan)", name, n, floor))
		}
	}
	if sites == 0 {
		errs = append(errs, fmt.Errorf("the scan found no nameHTML/textHTML(<participant inline text>) site at all: the gate would pass on nothing"))
	}
	// The declarations of nameHTML / textHTML (shared with trimName and serverErrorText
	// in sharedHelpers; the whole table is checked by TestSharedHelpers_*).
	errs = append(errs, checkSharedHelpers(portal, index, isolateHelpers)...)
	return errs
}

// The pinned declarations, as the mutations below need to name them.
var (
	nameHTMLWantLine = isolateHelpers[0].wantLine
	textHTMLWantLine = isolateHelpers[1].wantLine
)

func TestDisplayNames_IsolationHelpersAreTheSameLine(t *testing.T) {
	a := strings.ReplaceAll(isolateHelpers[0].wantLine, isolateHelpers[0].name, "H")
	b := strings.ReplaceAll(isolateHelpers[1].wantLine, isolateHelpers[1].name, "H")
	if a != b {
		t.Fatalf("nameHTML and textHTML must differ only in their name:\n  %s\n  %s", isolateHelpers[0].wantLine, isolateHelpers[1].wantLine)
	}
}

func TestDisplayNames_AreBidiIsolated(t *testing.T) {
	portal, index := portalSources(t)
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
		{"one nameHTML goes back to a bare esc", "hands participant inline text", false, func(s *bidiSrc) {
			s.portal["pane-scoreboard.tmpl"] = strings.Replace(s.portal["pane-scoreboard.tmpl"], "nameHTML(p.display_name || p.user)", "esc(p.display_name || p.user)", 1)
		}},
		{"a new partial escapes display_name bare", "hands participant inline text", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = esc(row.display_name);</script>"
		}},
		{"a new partial escapes authorDisplay bare", "hands participant inline text", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = `${esc(m.authorDisplay || m.author)}`;</script>"
		}},
		{"the Me pane escapes displayName bare", "hands participant inline text", false, func(s *bidiSrc) {
			s.portal["pane-me.tmpl"] = strings.Replace(s.portal["pane-me.tmpl"], "nameHTML(displayName)", "esc(displayName)", 1)
		}},
		{"a name is escaped around nameHTML", "escapes a value twice", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = esc(nameHTML(row.display_name));</script>"
		}},
		{"a name is escaped inside nameHTML", "escapes a value twice", false, func(s *bidiSrc) {
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
		{"the dashboard escapes a name bare", "hands participant inline text", false, func(s *bidiSrc) {
			s.index = strings.Replace(s.index, "nameHTML(s.display_name || s.user)", "esc(s.display_name || s.user)", 1)
		}},
		{"the dashboard loses its nameHTML", "index.html declares nameHTML 0 times", false, func(s *bidiSrc) {
			s.index = strings.Replace(s.index, nameHTMLWantLine, "", 1)
		}},
		// app#377: the board's subject is participant inline text too.
		{"a board subject goes back to a bare esc", "hands participant inline text", false, func(s *bidiSrc) {
			s.portal["pane-board.tmpl"] = strings.Replace(s.portal["pane-board.tmpl"], "textHTML(th.subject)", "esc(th.subject)", 1)
		}},
		{"a new partial escapes subject bare", "hands participant inline text", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = esc(t.subject);</script>"
		}},
		{"a subject is escaped around textHTML", "escapes a value twice", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = esc(textHTML(t.subject));</script>"
		}},
		{"a subject is escaped inside textHTML", "escapes a value twice", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>el.innerHTML = textHTML(esc(t.subject));</script>"
		}},
		{"a second textHTML declaration", "declares textHTML 2 times", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>const textHTML = (s) => esc(s);</script>"
		}},
		{"the textHTML declaration is gone", "declares textHTML 0 times", true, func(s *bidiSrc) {
			s.portal["core-util.tmpl"] = strings.Replace(s.portal["core-util.tmpl"], textHTMLWantLine, "", 1)
		}},
		{"textHTML stops using <bdi>", "not as the pinned line", true, func(s *bidiSrc) {
			s.portal["core-util.tmpl"] = strings.Replace(s.portal["core-util.tmpl"], textHTMLWantLine, `const textHTML = (s) => esc(s);`, 1)
		}},
		{"the dashboard declares textHTML (it renders no board)", "index.html declares textHTML 1 times, want exactly 0", true, func(s *bidiSrc) {
			s.index += "\n  " + textHTMLWantLine + "\n"
		}},
		// R1#1 (review-5x 19): the declaration and write forms escDeclRe / escWriteRe
		// catch for esc are caught for the isolating helpers too.
		{"textHTML in a declarator list", "declares textHTML 2 times", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>const a = 1, textHTML = (s) => s;</script>"
		}},
		{"textHTML by destructuring", "declares textHTML 2 times", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>const {textHTML} = window.helpers;</script>"
		}},
		{"nameHTML in a declarator list", "declares nameHTML 2 times", false, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>let a = 1, nameHTML = (s) => s;</script>"
		}},
		{"textHTML is reassigned", "never reassigned", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>textHTML = (s) => s;</script>"
		}},
		{"textHTML is reassigned with ||=", "never reassigned", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>textHTML ||= (s) => s;</script>"
		}},
		{"nameHTML is reassigned", "never reassigned", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>nameHTML = esc;</script>"
		}},
		{"textHTML is written as a property", "never reassigned", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>window.textHTML = (s) => s;</script>"
		}},
		{"textHTML is written through defineProperty", "never reassigned", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>Object.defineProperty(window, 'textHTML', { value: (s) => s });</script>"
		}},
		{"nameHTML is written through Object.assign", "never reassigned", true, func(s *bidiSrc) {
			s.portal["pane-new.tmpl"] = "<script>Object.assign(window, { 'nameHTML': (s) => s });</script>"
		}},
		// The floor, alone: the name is reached through an alias, which the scan
		// cannot see, so only the lower bound notices that a site is missing.
		{"a site is hidden behind an alias (floor only)", "want at least 6", true, func(s *bidiSrc) {
			s.portal["pane-scoreboard.tmpl"] = strings.Replace(s.portal["pane-scoreboard.tmpl"], "nameHTML(p.display_name || p.user)", "esc(nm)", 1)
		}},
		// F-1: the partial with a floor is renamed (and its site aliased), so the
		// floor's key matches no scanned file.
		{"a partial with a floor is renamed (floor key unmatched)", "floor but is not among the scanned files", true, func(s *bidiSrc) {
			s.portal["pane-profile.tmpl"] = strings.Replace(s.portal["pane-me.tmpl"], "nameHTML(displayName)", "esc(nm)", 1)
			delete(s.portal, "pane-me.tmpl")
		}},
		{"every site is gone", "site at all", false, func(s *bidiSrc) {
			for k := range s.portal {
				s.portal[k] = ""
			}
			s.index = ""
		}},
		// The zero-sites assert, alone: nothing but the pinned declarations,
		// and no floors, so the only thing wrong is that nothing is checked.
		{"nothing is scanned (zero sites only)", "site at all", true, func(s *bidiSrc) {
			s.portal = map[string]string{"core-util.tmpl": nameHTMLWantLine + "\n" + textHTMLWantLine + "\n"}
			s.index = "  " + nameHTMLWantLine + "\n"
			s.floors = nil
		}},
	}
	basePortal, baseIndex := portalSources(t)
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
