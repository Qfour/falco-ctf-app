package view

import (
	"fmt"
	"regexp"
	"sort"
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
// review are what cover that. first_solver is a username slug, not a name.
var inlineTextFields = []string{"display_name", "authorDisplay", "subject"}

// inlineTextLocals are bare local names that hold such a value (the Me pane's
// `displayName`).
var inlineTextLocals = []string{"displayName"}

// inlineTextArg makes an esc()/nameHTML()/textHTML() argument "participant
// inline text": x.<field> for a field above, or a bare local above.
var inlineTextArg = `(?:[A-Za-z_$][\w$]*\.(?:` + strings.Join(inlineTextFields, "|") + `)\b|(?:` + strings.Join(inlineTextLocals, "|") + `)\b)`

// sharedHelper is a helper declared once in the portal (core-util.tmpl) with its pinned
// declaration line, and how many times the admin dashboard (index.html, a separate
// document that does not load core-util.tmpl) declares it.
type sharedHelper struct {
	name, wantLine string
	portalDecls    int
	indexDecls     int
}

// nameEdgeClass is the character class of Go's strings.TrimSpace (unicode.IsSpace),
// as a JS regexp class. String.prototype.trim is not that set (app#401).
const nameEdgeClass = `\t\n\v\f\r \u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000`

// sharedHelpers is THE list of the helpers core-util.tmpl declares once for the
// portal, each with its pinned declaration. indexDecls 1 means index.html carries a
// byte-identical COPY (the dashboard does not load core-util.tmpl), so the rows with
// indexDecls 1 are the whole list of what the dashboard duplicates, i.e. #378's work
// list: when the dashboard's rendering is merged into the portal they go to 0 and the
// copies are deleted. nameHTML / textHTML isolate a participant-written string (the
// same one-liner, see core-util.tmpl; two names on purpose: nameHTML for a name,
// textHTML for prose, and TestDisplayNames_IsolationHelpersAreTheSameLine pins that the
// BODIES are one); the dashboard has its own esc, so its own nameHTML next to it, and
// no textHTML (it renders no board). trimName is the server's trim set for a name the
// portal sends, serverErrorText reads the server's {"error"} as a string (app#401).
// hasHiddenChar is the Cc / Cf class (minus U+200D) both the Profile name and a new
// board thread's subject pre-check with (app#408); index.html has no such form.
var sharedHelpers = []sharedHelper{
	{"nameHTML", `const nameHTML = (s) => '<bdi>' + esc(s) + '</bdi>';`, 1, 1},
	{"textHTML", `const textHTML = (s) => '<bdi>' + esc(s) + '</bdi>';`, 1, 0},
	{"trimName", `const trimName = (raw) => String(raw).replace(/^[` + nameEdgeClass + `]+|[` + nameEdgeClass + `]+$/g, '');`, 1, 1},
	{"serverErrorText", `const serverErrorText = async (r) => { try { const j = await r.json(); if (j && typeof j.error === 'string') return j.error; } catch (_) { /* no body */ } return ''; };`, 1, 1},
	{"hasHiddenChar", `const hasHiddenChar = (() => { let re = null; try { re = new RegExp('(?!\\u200D)[\\p{Cc}\\p{Cf}]', 'u'); } catch (_) { /* no \\p{..}: never refuse, the server decides */ } return (s) => re !== null && re.test(s); })();`, 1, 0},
}

// isolateHelpers are the two bidi-isolating rows of sharedHelpers.
var isolateHelpers = sharedHelpers[:2]

// checkSharedHelpers returns every violation of the one-declaration rule of helpers
// in the portal partials (name -> body) and the dashboard source: each is declared
// exactly portalDecls times across the partials and indexDecls times in index.html,
// as its pinned line (declRe finds the declaration forms, a shadow in a declarator
// list or by destructuring included), and never written to (writeRe).
func checkSharedHelpers(portal map[string]string, index string, helpers []sharedHelper) []error {
	var errs []error
	files := map[string]string{"index.html": index}
	for n, b := range portal {
		files[n] = b
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	portalDecls := map[string]int{}
	indexDecls := map[string]int{}
	for _, name := range names {
		body := stripEscComments(files[name])
		for _, h := range helpers {
			dre := declRe(h.name)
			d := len(dre.FindAllString(body, -1))
			// What is left once the pinned line and every declaration are cut out
			// can only be a write to the helper.
			rest := dre.ReplaceAllString(strings.ReplaceAll(body, h.wantLine, ""), "")
			for _, m := range writeRe(h.name).FindAllString(rest, -1) {
				errs = append(errs, fmt.Errorf("%s: found %q — %s must be declared once, as the pinned line, and never reassigned (a write swaps the helper for every pane)", name, strings.TrimSpace(m), h.name))
			}
			if name == "index.html" {
				indexDecls[h.name] += d
			} else {
				portalDecls[h.name] += d
			}
			if d > 0 && !strings.Contains(body, h.wantLine) {
				errs = append(errs, fmt.Errorf("%s declares %s, but not as the pinned line %q", name, h.name, h.wantLine))
			}
		}
	}
	for _, h := range helpers {
		if portalDecls[h.name] != h.portalDecls {
			errs = append(errs, fmt.Errorf("the portal declares %s %d times, want exactly %d (core-util.tmpl)", h.name, portalDecls[h.name], h.portalDecls))
		}
		if indexDecls[h.name] != h.indexDecls {
			errs = append(errs, fmt.Errorf("index.html declares %s %d times, want exactly %d", h.name, indexDecls[h.name], h.indexDecls))
		}
	}
	return errs
}

var (
	bareEscRe = regexp.MustCompile(`(?:^|[^\w$.])esc\(\s*` + inlineTextArg)
	// A site: an isolating helper called on participant inline text.
	isolatedUseRe = regexp.MustCompile(`(?:^|[^\w$.])(?:nameHTML|textHTML)\(\s*` + inlineTextArg)
	// esc(nameHTML(x)) shows the literal text "&lt;bdi&gt;"; nameHTML(esc(x))
	// escapes twice ("&amp;lt;"). Neither is an XSS, both are a broken display.
	doubleEscRe = regexp.MustCompile(`(?:^|[^\w$.])(?:esc\(\s*(?:nameHTML|textHTML)\(|(?:nameHTML|textHTML)\(\s*esc\()`)
)

// declRe finds a declaration of helper wherever on the line it sits, in the
// forms portal_partials_test.go's escDeclRe finds for esc: `function|const|let|
// var|class helper`, a declarator list `const a = x, helper = ...` and a
// destructuring `const {helper} = ...`. The pinned line is one such match.
func declRe(helper string) *regexp.Regexp {
	return regexp.MustCompile(`\b(?:function\*?|const|let|var|class)\s+` + helper + `\b|\b(?:const|let|var)\b[^;\n]*\b` + helper + `\b\s*(?:=|[,}\]])`)
}

// writeRe finds a write to helper that is not a declaration (escWriteRe's
// forms): bare `helper = ...` (also `||=`, `+=`; not ==, ===, =>), a property
// write `x.helper = ...` / `self['helper'] = ...`, and defineProperty /
// defineProperties / assign / set naming 'helper'. The scan runs on a body with
// the pinned line and the declaration matches already cut out. False positive by
// design, as for esc: `m.set('textHTML', v)`; rename the key rather than
// loosening the pattern.
func writeRe(helper string) *regexp.Regexp {
	return regexp.MustCompile("(?m)(?:^|[^\\w$.])" + helper + "\\s*(?:\\*\\*|<<|>>>?|&&|\\|\\||\\?\\?|[-+*/%&|^])?=(?:[^=>]|$)" +
		"|(?:\\.\\s*" + helper + "\\b|\\[\\s*['\"`]" + helper + "['\"`]\\s*\\])\\s*(?:\\*\\*|<<|>>>?|&&|\\|\\||\\?\\?|[-+*/%&|^])?=(?:[^=>]|$)" +
		"|\\b(?:defineProperty|defineProperties|assign|set)\\s*\\([^;\\n]*['\"`]" + helper + "['\"`]")
}

// bidiFloors are the numbers of isolated sites (nameHTML / textHTML on participant
// inline text) when this was written: scoreboard 5 (leaderboard row, activity, pod,
// challenge board, solver list), board 11 (6 names: public list, thread header,
// message authors, admin list and header; 5 subjects: my list, public list, thread
// header, admin list and header), Me 1, admin dashboard 5.
var bidiFloors = map[string]int{
	"pane-scoreboard.tmpl": 5,
	"pane-board.tmpl":      11,
	"pane-me.tmpl":         1,
	"index.html":           5,
}

// checkBidiNames returns every violation of the rule in the portal partials
// (name -> body) and the dashboard source. floors is the per-file lower bound
// on isolated sites; a file named in floors that is not among the scanned files
// is an error too (a renamed or split partial must not drop out of the floor
// silently).
func checkBidiNames(portal map[string]string, index string, floors map[string]int) []error {
	var errs []error
	files := map[string]string{"index.html": index}
	for n, b := range portal {
		files[n] = b
	}
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

func bidiSources(t *testing.T) (map[string]string, string) {
	t.Helper()
	portal := map[string]string{}
	for _, p := range portalPartials(t) {
		portal[p.name] = p.body
	}
	return portal, indexHTML
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
		{"a site is hidden behind an alias (floor only)", "want at least 5", true, func(s *bidiSrc) {
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

// TestSharedHelpers_OneDefinitionAndTheIndexCopy runs checkSharedHelpers over the real
// source: every row of sharedHelpers is declared once in the portal (core-util.tmpl) and
// the dashboard carries exactly the copies the table lists, as the pinned lines.
func TestSharedHelpers_OneDefinitionAndTheIndexCopy(t *testing.T) {
	portal, index := bidiSources(t)
	for _, err := range checkSharedHelpers(portal, index, sharedHelpers) {
		t.Error(err)
	}
}

// TestSharedHelpers_GateCatchesRegressions applies each edit that would split a shared
// helper (a shadow, a second definition, a write, a drifted or missing copy) to the real
// source and requires the gate to name it.
func TestSharedHelpers_GateCatchesRegressions(t *testing.T) {
	line := func(name string) string {
		for _, h := range sharedHelpers {
			if h.name == name {
				return h.wantLine
			}
		}
		t.Fatalf("no sharedHelpers row %s", name)
		return ""
	}
	type src struct {
		portal map[string]string
		index  string
	}
	cases := []struct {
		name   string
		want   string
		mutate func(s *src)
	}{
		{"pane-me declares its own trimName again", "the portal declares trimName 2 times", func(s *src) {
			s.portal["pane-me.tmpl"] += "\n<script>  function trimName(raw) { return String(raw).trim(); }</script>"
		}},
		{"trimName in a declarator list (a shadow)", "the portal declares trimName 2 times", func(s *src) {
			s.portal["pane-new.tmpl"] = "<script>const a = 1, trimName = (s) => s.trim();</script>"
		}},
		{"serverErrorText by destructuring", "the portal declares serverErrorText 2 times", func(s *src) {
			s.portal["pane-new.tmpl"] = "<script>const {serverErrorText} = window.helpers;</script>"
		}},
		{"trimName is reassigned", "never reassigned", func(s *src) {
			s.portal["pane-new.tmpl"] = "<script>trimName = (s) => s.trim();</script>"
		}},
		{"serverErrorText is written through defineProperty", "never reassigned", func(s *src) {
			s.portal["pane-new.tmpl"] = "<script>Object.defineProperty(window, 'serverErrorText', { value: () => '' });</script>"
		}},
		{"the trimName definition is gone", "the portal declares trimName 0 times", func(s *src) {
			s.portal["core-util.tmpl"] = strings.Replace(s.portal["core-util.tmpl"], line("trimName"), "", 1)
		}},
		{"core-util's trimName drifts from the pinned line", "not as the pinned line", func(s *src) {
			s.portal["core-util.tmpl"] = strings.Replace(s.portal["core-util.tmpl"], line("trimName"), "const trimName = (raw) => String(raw).trim();", 1)
		}},
		{"index.html's trimName drifts (String.prototype.trim)", "index.html declares trimName, but not as the pinned line", func(s *src) {
			s.index = strings.Replace(s.index, line("trimName"), "const trimName = (raw) => String(raw).trim();", 1)
		}},
		{"index.html's serverErrorText drifts", "index.html declares serverErrorText, but not as the pinned line", func(s *src) {
			s.index = strings.Replace(s.index, line("serverErrorText"), "const serverErrorText = async (r) => (await r.text());", 1)
		}},
		{"index.html loses its serverErrorText copy", "index.html declares serverErrorText 0 times", func(s *src) {
			s.index = strings.Replace(s.index, line("serverErrorText"), "", 1)
		}},
		{"index.html declares trimName twice", "index.html declares trimName 2 times", func(s *src) {
			s.index += "\n  " + line("trimName") + "\n"
		}},
		{"hasHiddenChar is declared again in pane-board", "the portal declares hasHiddenChar 2 times", func(s *src) {
			s.portal["pane-board.tmpl"] += "\n<script>  const hasHiddenChar = (s) => /[\\u0000-\\u001f]/.test(s);</script>"
		}},
		{"hasHiddenChar is added to index.html", "index.html declares hasHiddenChar 1 times, want exactly 0", func(s *src) {
			s.index += "\n  " + line("hasHiddenChar") + "\n"
		}},
	}
	basePortal, baseIndex := bidiSources(t)
	if errs := checkSharedHelpers(basePortal, baseIndex, sharedHelpers); len(errs) != 0 {
		t.Fatalf("the unmodified source must pass the gate first: %v", errs)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := src{portal: map[string]string{}, index: baseIndex}
			for k, v := range basePortal {
				m.portal[k] = v
			}
			c.mutate(&m)
			errs := checkSharedHelpers(m.portal, m.index, sharedHelpers)
			found := false
			for _, err := range errs {
				if strings.Contains(err.Error(), c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no error contains %q; got %v", c.want, errs)
			}
		})
	}
}

// checkHiddenCharClass returns every file (a portal partial or index.html) that writes the
// Cc / Cf class itself instead of calling hasHiddenChar: the class has ONE definition,
// core-util.tmpl's pinned line (app#408). Comments are stripped first (core-util's own doc
// names the class), and the pinned line is cut out.
func checkHiddenCharClass(portal map[string]string, index string, pinned string) []error {
	files := map[string]string{"index.html": index}
	for n, b := range portal {
		files[n] = b
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		body := strings.ReplaceAll(stripEscComments(files[n]), pinned, "")
		for _, class := range []string{`\p{Cc}`, `\p{Cf}`} {
			if strings.Contains(body, class) {
				errs = append(errs, fmt.Errorf("%s writes %s itself: the Cc/Cf class is hasHiddenChar's (core-util.tmpl), the one definition shared by the Profile name and the board subject", n, class))
			}
		}
	}
	return errs
}

func TestHiddenCharClass_HasOneDefinition(t *testing.T) {
	portal, index := bidiSources(t)
	var pinned string
	for _, h := range sharedHelpers {
		if h.name == "hasHiddenChar" {
			pinned = h.wantLine
		}
	}
	if pinned == "" {
		t.Fatal("no sharedHelpers row hasHiddenChar")
	}
	for _, err := range checkHiddenCharClass(portal, index, pinned) {
		t.Error(err)
	}
	// The gate must see a restatement, in any partial or in the dashboard.
	for _, m := range []struct {
		name   string
		mutate func(p map[string]string, idx *string)
	}{
		{"pane-me restates the class inline", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] += "\n<script>const x = (s) => /[\\p{Cc}]/u.test(s);</script>"
		}},
		{"pane-board restates Cf", func(p map[string]string, _ *string) {
			p["pane-board.tmpl"] += "\n<script>const y = new RegExp('\\\\p{Cf}', 'u');</script>"
		}},
		{"index.html restates the class", func(_ map[string]string, idx *string) {
			*idx += "\n<script>const z = /\\p{Cc}/u;</script>"
		}},
	} {
		t.Run(m.name, func(t *testing.T) {
			p := map[string]string{}
			for k, v := range portal {
				p[k] = v
			}
			idx := index
			m.mutate(p, &idx)
			if len(checkHiddenCharClass(p, idx, pinned)) == 0 {
				t.Error("the gate did not catch a restated Cc/Cf class")
			}
		})
	}
}
