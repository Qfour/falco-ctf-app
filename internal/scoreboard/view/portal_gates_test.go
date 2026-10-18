package view

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The portal's source gates that are not about bidi isolation (they were in
// portal_bidi_test.go, which they outgrew; test names and assertions are unchanged, only the
// files collection and the pinned-line lookup became the helpers below). One
// declaration of each shared helper (sharedHelpers), the server's {"error"} read in
// one place (errorFieldReads), the board's strings trimmed with trimName (bodyTrim),
// the Cc / Cf class defined once (hiddenCharClass). portal_bidi_test.go keeps the
// isolation gate and uses the helper table and the source collection from here.
//
// Where a gate lives: the one-declaration rule of every helper in sharedHelpers is here
// (declRe / writeRe are its forms). The one-definition gate of esc is NOT: it stays in
// portal_partials_test.go, because it also checks what a declaration-and-write scan cannot
// (the pinned line verbatim, TDZ: the definition before the first pane, and the call order
// of the partials). escDeclRe / escWriteRe there are declRe("esc") / writeRe("esc"), so the
// forms are defined once; a new shared helper is a row in sharedHelpers, not a new gate.

// scannedSources is every file the gates in this file and in portal_bidi_test.go scan: the
// portal partials by name plus the admin dashboard as "index.html", and the names sorted (a
// stable error order). The one place those gates merge the two sources. (The esc gate in
// portal_partials_test.go reads the partials only and does not use it.)
func scannedSources(portal map[string]string, index string) (map[string]string, []string) {
	files := map[string]string{"index.html": index}
	for n, b := range portal {
		files[n] = b
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return files, names
}

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
// BODIES are one; rows 0 and 1 stay nameHTML and textHTML, portal_bidi_test.go reads them
// by position as isolateHelpers); the dashboard has its own esc, so its own nameHTML next to it, and
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
	files, names := scannedSources(portal, index)
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

// declRe finds a declaration of helper wherever on the line it sits, in these forms
// (the esc gate's escDeclRe in portal_partials_test.go is declRe("esc")): `function|const|let|
// var|class helper`, a declarator list `const a = x, helper = ...` and a
// destructuring `const {helper} = ...`. The pinned line is one such match.
func declRe(helper string) *regexp.Regexp {
	return regexp.MustCompile(`\b(?:function\*?|const|let|var|class)\s+` + helper + `\b|\b(?:const|let|var)\b[^;\n]*\b` + helper + `\b\s*(?:=|[,}\]])`)
}

// writeRe finds a write to helper that is not a declaration (the esc gate's escWriteRe = writeRe("esc")
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

// portalSources is the real source in the shape those gates take: portalPartials by name
// (the portal map) and indexHTML (the dashboard).
func portalSources(t *testing.T) (map[string]string, string) {
	t.Helper()
	portal := map[string]string{}
	for _, p := range portalPartials(t) {
		portal[p.name] = p.body
	}
	return portal, indexHTML
}

// TestSharedHelpers_OneDefinitionAndTheIndexCopy runs checkSharedHelpers over the real
// source: every row of sharedHelpers is declared once in the portal (core-util.tmpl) and
// the dashboard carries exactly the copies the table lists, as the pinned lines.
func TestSharedHelpers_OneDefinitionAndTheIndexCopy(t *testing.T) {
	portal, index := portalSources(t)
	for _, err := range checkSharedHelpers(portal, index, sharedHelpers) {
		t.Error(err)
	}
}

// TestSharedHelpers_GateCatchesRegressions applies each edit that would split a shared
// helper (a shadow, a second definition, a write, a drifted or missing copy) to the real
// source and requires the gate to name it.
func TestSharedHelpers_GateCatchesRegressions(t *testing.T) {
	line := func(name string) string { return sharedHelperLine(t, name) }
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
	basePortal, baseIndex := portalSources(t)
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

// errorFieldRe finds a read of a response's `error` field: `x.error`, `x?.error`,
// `x['error']`, and a destructuring that takes it (`const { error } = ...`, a parameter
// `({ error }) => ...`). console.error is a call, not a read of a response (the one
// allowed receiver, see checkErrorFieldReads).
var errorFieldRe = regexp.MustCompile(`([\w$\])]*)\??\.\s*error\b` +
	`|\[\s*['"` + "`" + `]error['"` + "`" + `]\s*\]` +
	`|\b(?:const|let|var)\b[^;\n]*\{[^}\n]*\berror\b[^}\n]*\}\s*=[^=]` +
	`|\(\s*\{[^})\n]*\berror\b[^})\n]*\}\s*[,)]`)

// checkErrorFieldReads returns every file (a portal partial or index.html) that reads the
// response's `error` field other than through serverErrorText. That is the property it
// checks: the field is read in ONE place, core-util.tmpl's pinned line (and index.html's
// byte-identical copy of it). Comments are stripped and every pinned line is cut out.
func checkErrorFieldReads(portal map[string]string, index string, pinned string) []error {
	files, names := scannedSources(portal, index)
	var errs []error
	for _, n := range names {
		body := strings.ReplaceAll(stripEscComments(files[n]), pinned, "")
		for _, m := range errorFieldRe.FindAllStringSubmatch(body, -1) {
			if m[1] == "console" {
				continue
			}
			errs = append(errs, fmt.Errorf("%s reads %q: the server's {\"error\"} is read by serverErrorText (core-util.tmpl) only, as a string, so every path shows it the same way and falls back the same way", n, strings.TrimSpace(m[0])))
		}
	}
	return errs
}

// checkBoardBodyTrim returns every String.prototype.trim call in pane-board.tmpl: the
// board's strings (subject and body) are trimmed with trimName (core-util.tmpl), the server's
// trim set. trim() strips U+FEFF (the server keeps it) and keeps a trailing U+0085 (the server
// strips it), so a form using it disagrees with the server about "empty" and "too long".
func checkBoardBodyTrim(portal map[string]string) []error {
	pane, ok := portal["pane-board.tmpl"]
	if !ok {
		return []error{fmt.Errorf("pane-board.tmpl is not among the scanned partials (renamed? move this gate with it)")}
	}
	var errs []error
	for _, m := range regexp.MustCompile(`\.trim(?:Start|End|Left|Right)?\s*\(`).FindAllString(stripEscComments(pane), -1) {
		errs = append(errs, fmt.Errorf("pane-board.tmpl calls %q: trim a board string with trimName (core-util.tmpl), the server's trim set, not String.prototype.trim", strings.TrimSpace(m)))
	}
	return errs
}

func sharedHelperLine(t *testing.T, name string) string {
	t.Helper()
	for _, h := range sharedHelpers {
		if h.name == name {
			return h.wantLine
		}
	}
	t.Fatalf("no sharedHelpers row %s", name)
	return ""
}

// TestErrorFieldReads_OnlyServerErrorTextReadsIt runs both new gates over the real source
// and requires them to see the edits that would bring the old behaviour back: a handler that
// reads d.error (or a bracket form) itself, a trim() in pane-board, in either spelling.
func TestErrorFieldReads_OnlyServerErrorTextReadsIt(t *testing.T) {
	portal, index := portalSources(t)
	pinned := sharedHelperLine(t, "serverErrorText")
	for _, err := range checkErrorFieldReads(portal, index, pinned) {
		t.Error(err)
	}
	for _, err := range checkBoardBodyTrim(portal) {
		t.Error(err)
	}
	cases := []struct {
		name   string
		want   string
		mutate func(p map[string]string, idx *string)
		gate   func(p map[string]string, idx string) []error
	}{
		{"a board path reads d.error again", "reads \"d.error\"", func(p map[string]string, _ *string) {
			p["pane-board.tmpl"] = strings.Replace(p["pane-board.tmpl"], "(await serverErrorText(r)) ||", "d.error ||", 1)
		}, nil},
		{"a path reads the bracket form", "reads \"['error']\"", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] += "\n<script>const w = j['error'];</script>"
		}, nil},
		{"index.html reads j?.error", "reads \"j?.error\"", func(_ map[string]string, idx *string) {
			*idx += "\n<script>const w = j?.error;</script>"
		}, nil},
		{"index.html's reset handler reads the field", "index.html reads", func(_ map[string]string, idx *string) {
			*idx += "\n<script>alert('Reset failed: ' + (await r.json()).error);</script>"
		}, nil},
		{"a path destructures {error}", "reads \"const { error } =\"", func(p map[string]string, _ *string) {
			p["pane-board.tmpl"] += "\n<script>const { error } = await r.json();</script>"
		}, nil},
		{"a path destructures {error} in a parameter", "reads \"({ error })\"", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] += "\n<script>r.json().then(({ error }) => alert(error));</script>"
		}, nil},
		{"a destructuring of other fields is not a read of error", "", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] += "\n<script>const { id, state } = await r.json(); const o = { error: 1 };</script>"
		}, nil},
		{"console.error is not a read of a response", "", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] += "\n<script>console.error(e);</script>"
		}, nil},
		{"a second copy of the pinned line is still cut out (the declaration count is the other gate's)", "", func(p map[string]string, _ *string) {
			p["pane-me.tmpl"] += "\n<script>" + pinned + "</script>"
		}, nil},
		{"pane-board trims a body with trim()", "calls \".trim(\"", func(p map[string]string, _ *string) {
			p["pane-board.tmpl"] = strings.Replace(p["pane-board.tmpl"], "trimName(bodyEl.value)", "bodyEl.value.trim()", 1)
		}, func(p map[string]string, _ string) []error { return checkBoardBodyTrim(p) }},
		{"pane-board trims with trimEnd()", "calls \".trimEnd (\"", func(p map[string]string, _ *string) {
			p["pane-board.tmpl"] += "\n<script>const q = x.trimEnd ();</script>"
		}, func(p map[string]string, _ string) []error { return checkBoardBodyTrim(p) }},
		{"pane-board is gone", "not among the scanned", func(p map[string]string, _ *string) {
			delete(p, "pane-board.tmpl")
		}, func(p map[string]string, _ string) []error { return checkBoardBodyTrim(p) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := map[string]string{}
			for k, v := range portal {
				p[k] = v
			}
			idx := index
			c.mutate(p, &idx)
			var errs []error
			if c.gate != nil {
				errs = c.gate(p, idx)
			} else {
				errs = checkErrorFieldReads(p, idx, pinned)
			}
			if c.want == "" {
				if len(errs) != 0 {
					t.Errorf("must pass, got %v", errs)
				}
				return
			}
			for _, err := range errs {
				if strings.Contains(err.Error(), c.want) {
					return
				}
			}
			t.Errorf("no error contains %q; got %v", c.want, errs)
		})
	}
}

// checkHiddenCharClass returns every file (a portal partial or index.html) that writes the
// Cc / Cf class itself instead of calling hasHiddenChar: the class has ONE definition,
// core-util.tmpl's pinned line (app#408). Comments are stripped first (core-util's own doc
// names the class), and the pinned line is cut out.
func checkHiddenCharClass(portal map[string]string, index string, pinned string) []error {
	files, names := scannedSources(portal, index)
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
	portal, index := portalSources(t)
	pinned := sharedHelperLine(t, "hasHiddenChar")
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
