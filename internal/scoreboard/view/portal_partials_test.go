package view

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"text/template/parse"
)

// portalLastPartial is the partial the root must call LAST. Call order is
// fixed by rule rather than by pinning the whole list, so panes can still
// be added or reordered freely; a PR that adds another order-dependent
// partial adds its own rule: to checkPortalAssembly for a plain call-order
// rule (this one), or to its own check when the rule is about a script's
// content (esc: checkPortalEsc, which reads the order from rootCallOrder).
//
// Why the router is last: core-router.tmpl:74-76 runs applyRole() and
// showTab(currentTab()) the moment its <script> is parsed. showTab looks
// each pane up by id and skips one that is not in the DOM yet
// (core-router.tmpl:39-40, `if (pane) ...`), and css.tmpl:48-49 hides every
// pane that is not .active. So with the router ahead of the panes the first
// paint shows no pane at all, and a pane added after the router is never
// shown on first paint. Nothing else catches that: the other checks count
// calls, not their order, and no test executes the page's JS.
const portalLastPartial = "core-router.tmpl"

// portalPartial is one templates/portal/*.tmpl source file.
type portalPartial struct {
	name string // basename == html/template name
	body string
}

// readPortalPartials returns every file in fsys matching portalTmplGlob,
// sorted by name. It errors when it finds nothing, when a file is empty, and
// when the root shell is not among what it found: a source-level gate that
// tolerates an empty list is green forever.
func readPortalPartials(fsys fs.FS) ([]portalPartial, error) {
	names, err := fs.Glob(fsys, portalTmplGlob)
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", portalTmplGlob, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no portal partials match %s — every source-level gate over the portal would be scanning nothing", portalTmplGlob)
	}
	sort.Strings(names)
	out := make([]portalPartial, 0, len(names))
	hasRoot := false
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", n, err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("%s is empty", n)
		}
		base := path.Base(n)
		hasRoot = hasRoot || base == portalRootTmpl
		out = append(out, portalPartial{name: base, body: string(b)})
	}
	if !hasRoot {
		return nil, fmt.Errorf("root shell %s is not among the partials %v", portalRootTmpl, names)
	}
	return out, nil
}

// portalPartials is the ONE way a test should get at the embedded portal
// template source (P28-0a): a gate that names files individually silently
// stops covering a partial added later. Fails the calling test when
// readPortalPartials does.
func portalPartials(t *testing.T) []portalPartial {
	t.Helper()
	parts, err := readPortalPartials(portalFS)
	if err != nil {
		t.Fatal(err)
	}
	return parts
}

// templateCalls returns every {{template}} action reachable in n, including
// those nested under if/range/with. checkPortalAssembly uses it to FIND
// nested calls so it can reject them; only a call that is a direct child of
// the root's top-level list counts as composing a partial.
func templateCalls(n parse.Node) []*parse.TemplateNode {
	var out []*parse.TemplateNode
	var walk func(parse.Node)
	branch := func(b *parse.BranchNode) {
		if b.List != nil {
			walk(b.List)
		}
		if b.ElseList != nil {
			walk(b.ElseList)
		}
	}
	walk = func(n parse.Node) {
		switch v := n.(type) {
		case *parse.ListNode:
			if v == nil {
				return
			}
			for _, c := range v.Nodes {
				walk(c)
			}
		case *parse.TemplateNode:
			out = append(out, v)
		case *parse.IfNode:
			branch(&v.BranchNode)
		case *parse.RangeNode:
			branch(&v.BranchNode)
		case *parse.WithNode:
			branch(&v.BranchNode)
		}
	}
	walk(n)
	return out
}

// pipeIsDot reports whether a {{template "x" PIPE}} argument is exactly `.`.
func pipeIsDot(p *parse.PipeNode) bool {
	if p == nil || len(p.Decl) != 0 || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 1 {
		return false
	}
	_, ok := p.Cmds[0].Args[0].(*parse.DotNode)
	return ok
}

// checkPortalAssembly verifies the assembly contract of the portal partials
// in fsys and returns every violation found (nil when there is none). It
// judges the PARSE TREE of each file, not its text, so spacing and trim
// markers inside an action (`{{ template "x" . }}`, `{{- define "x" -}}`)
// cannot hide one. html/template itself reports none of these at init: a
// call to a missing name fails only on first Execute, and the rest never
// fail at all.
//
//  1. Each file, parsed alone, defines exactly one template, named after the
//     file. A {{define}}/{{block}} adds a second one; ParseFS reads files in
//     name order and the last definition of a name wins, so a define in one
//     file can silently replace ANOTHER partial's body while that partial's
//     own file is unchanged — "the diff of a partial is the diff of what is
//     served" would stop being true.
//
//  2. The root composes every other partial UNCONDITIONALLY, exactly once:
//     each is called by a {{template}} action that is a direct child of the
//     root's top-level node list, with `.` as the argument (without it the
//     partial sees no data: every {{.Nonce}} renders empty and CSP blocks
//     that script), and the root calls nothing that is not a partial. A
//     call inside {{if}}/{{range}}/{{with}} is a violation and is not
//     counted: whether (and how many times) it is served would depend on
//     data, which a static check cannot decide — `{{if false}}` drops the
//     pane, `{{range}}` repeats it. Uncalled = passes the source gates but
//     is never served; called twice = duplicate element ids.
//
//  3. No partial other than the root calls a template (flat layout).
//
//  4. The root's LAST call is portalLastPartial (see its doc).
//
//  5. html/template, parsing the same files the way view.go does, ends up
//     with exactly one template per file and no other name — the same
//     last-definition-wins hazard as (1), seen from the parsed set (it also
//     covers two files sharing a basename, should the glob ever widen).
//
// Not checked: the trailing trim marker on a call. Leaving it off only emits
// one extra newline between elements.
func checkPortalAssembly(fsys fs.FS) error {
	parts, err := readPortalPartials(fsys)
	if err != nil {
		return err
	}
	var errs []error
	have := map[string]bool{}
	calls := map[string]int{}
	lastCall := "" // name of the root's final {{template}} call, in document order
	for _, p := range parts {
		have[p.name] = true
		tr := parse.New(p.name)
		// Only structure matters here; do not fail on a function the bare
		// parser does not know (html/template resolves those itself).
		tr.Mode = parse.SkipFuncCheck
		set := map[string]*parse.Tree{}
		if _, err := tr.Parse(p.body, "", "", set); err != nil {
			errs = append(errs, fmt.Errorf("%s: parse: %w", p.name, err))
			continue
		}
		defined := make([]string, 0, len(set))
		for name := range set {
			defined = append(defined, name)
		}
		sort.Strings(defined)
		if len(defined) != 1 || defined[0] != p.name {
			errs = append(errs, fmt.Errorf("%s defines template(s) %q, want exactly [%q] — a partial must not contain {{define}}/{{block}}", p.name, defined, p.name))
		}
		for name, tree := range set {
			topLevel := map[*parse.TemplateNode]bool{}
			if tree.Root != nil {
				for _, n := range tree.Root.Nodes {
					if c, ok := n.(*parse.TemplateNode); ok {
						topLevel[c] = true
					}
				}
			}
			for _, c := range templateCalls(tree.Root) {
				if p.name != portalRootTmpl || name != portalRootTmpl {
					errs = append(errs, fmt.Errorf("%s calls template %q — only the root %s composes partials (flat layout)", p.name, c.Name, portalRootTmpl))
					continue
				}
				if !topLevel[c] {
					errs = append(errs, fmt.Errorf("%s calls %q inside {{if}}/{{range}}/{{with}} — the root must compose every partial unconditionally, at its top level", p.name, c.Name))
					continue
				}
				calls[c.Name]++
				lastCall = c.Name
				if !pipeIsDot(c.Pipe) {
					errs = append(errs, fmt.Errorf("%s calls %q without `.` as its argument — the partial would receive no data (empty nonce)", p.name, c.Name))
				}
			}
		}
	}
	for _, p := range parts {
		if p.name == portalRootTmpl {
			if calls[p.name] != 0 {
				errs = append(errs, fmt.Errorf("root %s calls itself", p.name))
			}
			continue
		}
		if got := calls[p.name]; got != 1 {
			errs = append(errs, fmt.Errorf("partial %s is called %d time(s) from %s, want exactly 1", p.name, got, portalRootTmpl))
		}
	}
	callNames := make([]string, 0, len(calls))
	for name := range calls {
		callNames = append(callNames, name)
	}
	sort.Strings(callNames)
	for _, name := range callNames {
		if !have[name] {
			errs = append(errs, fmt.Errorf("root %s calls %q, which is not a partial file", portalRootTmpl, name))
		}
	}
	if lastCall != portalLastPartial {
		errs = append(errs, fmt.Errorf("root %s's last {{template}} call is %q, want %q — the router must come after every pane (see portalLastPartial)", portalRootTmpl, lastCall, portalLastPartial))
	}

	tmpl, err := template.New(portalRootTmpl).ParseFS(fsys, portalTmplGlob)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("html/template parse: %w", err))...)
	}
	var defined, files []string
	for _, t := range tmpl.Templates() {
		defined = append(defined, t.Name())
	}
	for _, p := range parts {
		files = append(files, p.name)
	}
	sort.Strings(defined)
	sort.Strings(files)
	if strings.Join(defined, "\n") != strings.Join(files, "\n") {
		errs = append(errs, fmt.Errorf("html/template defines %q but the partial files are %q — the two sets must be equal", defined, files))
	}
	return errors.Join(errs...)
}

var (
	// Open/close tags are matched at line start: that is how every real one
	// is written in these files, and it keeps prose mentions inside comments
	// and JS strings ("a future inline <script> ...") out of the count. The
	// rendered-count cross-check below catches a tag written any other way.
	// Case-insensitive, as HTML tag names are.
	srcScriptOpenRe  = regexp.MustCompile(`(?im)^<script\b[^>]*>`)
	srcScriptCloseRe = regexp.MustCompile(`(?im)^</script>`)
	srcStyleOpenRe   = regexp.MustCompile(`(?im)^<style\b[^>]*>`)
	srcStyleCloseRe  = regexp.MustCompile(`(?im)^</style>`)
	anyScriptOpenRe  = regexp.MustCompile(`(?i)<script\b`)
	anyStyleOpenRe   = regexp.MustCompile(`(?i)<style\b`)
)

// checkPortalScriptAndStyle verifies, per partial and at SOURCE level, that
// no <script>/<style> element straddles a partial boundary (a cut made
// mid-element would shift html/template's escaping context across it) and
// that every <script> open tag is exactly `<script nonce="{{.Nonce}}">`.
// It then renders the document assembled from fsys and requires the number
// of <script> and <style> tags served to equal the number the source scan
// saw, so a tag the line-start matcher cannot see (indented, or injected by
// a second call) is a failure instead of an unchecked tag.
func checkPortalScriptAndStyle(fsys fs.FS) error {
	parts, err := readPortalPartials(fsys)
	if err != nil {
		return err
	}
	const wantOpen = `<script nonce="{{.Nonce}}">`
	var errs []error
	scripts, styles := 0, 0
	for _, p := range parts {
		opens := srcScriptOpenRe.FindAllString(p.body, -1)
		if c := len(srcScriptCloseRe.FindAllString(p.body, -1)); c != len(opens) {
			errs = append(errs, fmt.Errorf("%s: %d <script> open tag(s) but %d </script> — a script block must not straddle partials", p.name, len(opens), c))
		}
		o, c := len(srcStyleOpenRe.FindAllString(p.body, -1)), len(srcStyleCloseRe.FindAllString(p.body, -1))
		if o != c {
			errs = append(errs, fmt.Errorf("%s: %d <style> open tag(s) but %d </style> — a style block must not straddle partials", p.name, o, c))
		}
		for _, tag := range opens {
			if tag != wantOpen {
				errs = append(errs, fmt.Errorf("%s: script open tag %q, want exactly %q (CSP script-src is nonce-only; an un-nonced inline script is silently blocked)", p.name, tag, wantOpen))
			}
		}
		scripts += len(opens)
		styles += o
	}
	if scripts == 0 || styles == 0 {
		errs = append(errs, fmt.Errorf("source scan found %d <script> and %d <style> open tag(s) — the line-start matcher no longer matches how these files are written, so this check is checking nothing", scripts, styles))
	}

	tmpl, err := template.New(portalRootTmpl).ParseFS(fsys, portalTmplGlob)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("parse portal: %w", err))...)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, portalData{Nonce: "test-nonce", Assets: staticAssets}); err != nil {
		return errors.Join(append(errs, fmt.Errorf("execute portal: %w", err))...)
	}
	if got := len(anyScriptOpenRe.FindAllString(buf.String(), -1)); got != scripts {
		errs = append(errs, fmt.Errorf("rendered portal has %d <script> tag(s) but the partials' line-start open tags total %d — a script tag is served that the source scan does not cover", got, scripts))
	}
	if got := len(anyStyleOpenRe.FindAllString(buf.String(), -1)); got != styles {
		errs = append(errs, fmt.Errorf("rendered portal has %d <style> tag(s) but the partials' line-start open tags total %d — a style tag is served that the source scan does not cover", got, styles))
	}
	return errors.Join(errs...)
}

// escWantLine is the ONE declaration of esc the portal may contain, pinned
// verbatim. esc is the portal's only HTML-escape path, so what it does is the
// XSS defence of every pane: a counting check ("one definition, before the
// panes") passes a body with the `.replace` cut out or `"'` dropped from the
// character class, which is why the whole line is compared. It is an arrow
// bound by a top-level `const` (see core-util.tmpl for why that form): a
// reassignment is a TypeError and a redeclaration a SyntaxError. Changing the
// escaper means changing this constant, in a commit that says why.
const escWantLine = `const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));`

var (
	// Whole-line `//` comments and `<!-- -->` comments are removed before
	// scanning, so prose that names esc (core-util.tmpl documents every way
	// of replacing it) is not a finding. Trailing `// ...` after code and
	// `/* */` blocks are NOT removed: stripping them could hide code after a
	// "/*" or "//" inside a string, and leaving them can only add a false
	// positive, the safe direction.
	escLineCommentRe = regexp.MustCompile(`(?m)^[ \t]*//.*$`)
	escHTMLCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)

	// A second declaration of esc, wherever on the line it sits (after `;`,
	// `{`, in a comma list, indented inside an IIFE): `function esc` (also
	// async / generator), `const|let|var|class esc`, a declarator list
	// `const a = x, esc = ...` or a destructuring `const {esc} = ...`.
	escDeclRe = regexp.MustCompile(`\b(?:function\*?|const|let|var|class)\s+esc\b|\b(?:const|let|var)\b[^;\n]*\besc\b\s*(?:=|[,}\]])`)

	// A write to esc that is not a declaration: bare `esc = ...` (also
	// `esc ||= ...`, `esc += ...`; not ==, ===, =>), a property write
	// `x.esc = ...` / `self['esc'] = ...` / `globalThis.esc = ...`, and the
	// reflective forms Object.defineProperty / defineProperties / assign and
	// Reflect.set / defineProperty naming 'esc'. Against the const binding
	// most of these are inert at run time, but none has a reason to exist
	// and each is exactly what a later edit would use to swap the escaper.
	// False positive by design: the `set(` branch also matches a legitimate
	// call such as `keys.set('esc', back)` (a Map keyed by the string "esc").
	// Rename the key or the variable rather than loosening this pattern.
	escWriteRe = regexp.MustCompile("(?m)(?:^|[^\\w$.])esc\\s*(?:\\*\\*|<<|>>>?|&&|\\|\\||\\?\\?|[-+*/%&|^])?=(?:[^=>]|$)" +
		"|(?:\\.\\s*esc\\b|\\[\\s*['\"`]esc['\"`]\\s*\\])\\s*(?:\\*\\*|<<|>>>?|&&|\\|\\||\\?\\?|[-+*/%&|^])?=(?:[^=>]|$)" +
		"|\\b(?:defineProperty|defineProperties|assign|set)\\s*\\([^;\\n]*['\"`]esc['\"`]")

	// A use of esc: a call `esc(` or a reference such as `.map(esc)` — not a
	// property (`x.esc`), an object key (`esc:`) or part of a longer name.
	escUseRe = regexp.MustCompile(`(?m)(?:^|[^\w$.])esc(?:[^\w$:]|$)`)
)

// stripEscComments removes the comment forms escLineCommentRe and
// escHTMLCommentRe describe.
func stripEscComments(s string) string {
	return escLineCommentRe.ReplaceAllString(escHTMLCommentRe.ReplaceAllString(s, ""), "")
}

// escIsFirstStatement reports whether the declaration at byte offset at in
// code is the first statement of its <script>: everything between the
// script's open tag and at is whitespace (comments are already stripped from
// code). That one condition gives both properties esc needs.
//
//   - Top level: a declaration inside an IIFE, function or block is private
//     to that scope, and no other partial's script can reach it.
//   - No TDZ window: esc is a const, so a statement BEFORE it that throws
//     aborts the script and leaves esc uninitialised for good — every pane
//     then fails with "Cannot access 'esc' before initialization" (a
//     function declaration would have been hoisted and survived). Nothing
//     can precede it, so nothing can throw first. A helper added to this
//     partial later therefore goes after the esc line.
func escIsFirstStatement(code string, at int) bool {
	head := code[:at]
	if i := strings.LastIndex(strings.ToLower(head), "<script"); i >= 0 {
		if j := strings.Index(head[i:], ">"); j >= 0 {
			head = head[i+j+1:]
		}
	}
	return strings.TrimSpace(head) == ""
}

// rootCallOrder returns the names the root calls at its top level, in
// document order (the order html/template serves them). TODO: this parses
// the root the same way checkPortalAssembly does (the parse.New / SkipFuncCheck
// block over each partial); fold the two into one shared helper the next time
// either is touched.
func rootCallOrder(fsys fs.FS) ([]string, error) {
	b, err := fs.ReadFile(fsys, path.Dir(portalTmplGlob)+"/"+portalRootTmpl)
	if err != nil {
		return nil, err
	}
	tr := parse.New(portalRootTmpl)
	tr.Mode = parse.SkipFuncCheck
	set := map[string]*parse.Tree{}
	if _, err := tr.Parse(string(b), "", "", set); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", portalRootTmpl, err)
	}
	var order []string
	if root := set[portalRootTmpl]; root != nil && root.Root != nil {
		for _, n := range root.Root.Nodes {
			if c, ok := n.(*parse.TemplateNode); ok {
				order = append(order, c.Name)
			}
		}
	}
	return order, nil
}

// checkPortalEsc verifies the single-escape-path rule (P28-0a), returning
// every violation (nil when there is none):
//
//  1. Exactly one partial, in the whole portal, contains escWantLine, as a
//     whole line starting at column 0 and exactly once. The escaper's body is
//     compared, not just counted (see escWantLine).
//
//  2. That line is the FIRST statement of its script (escIsFirstStatement):
//     top level, so it is a global binding and not private to an IIFE, and
//     nothing before it that could throw and leave the const in its TDZ.
//
//  3. No partial, the declaring one included, declares or writes the name
//     anywhere else (escDeclRe, escWriteRe): no local copy that shadows the
//     shared one, no `esc = ...` / `self.esc = ...` / `window['esc'] = ...`
//     / Object.defineProperty(window, 'esc', ...) that swaps it. This is a
//     source scan, not a proof: `eval`, `with`, computed property names and
//     the like are out of reach of a regex and are the reviewer's to catch.
//
//  4. The partial that declares esc is called by the root at its top level
//     before every other partial that uses it (call or reference, escUseRe),
//     and before any use of esc in the root's own inline script. A use served
//     earlier is a ReferenceError at that pane's first render, which no Go
//     test would otherwise see.
func checkPortalEsc(fsys fs.FS) error {
	parts, err := readPortalPartials(fsys)
	if err != nil {
		return err
	}
	var errs []error
	wantLineRe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(escWantLine) + `[ \t]*$`)

	// code is each partial with comments removed and, in the declaring
	// partial, the one permitted declaration line removed.
	code := map[string]string{}
	definer, declAt := "", -1
	total := 0
	for _, p := range parts {
		c := stripEscComments(p.body)
		locs := wantLineRe.FindAllStringIndex(c, -1)
		total += len(locs)
		if len(locs) > 0 {
			definer = p.name
			if len(locs) == 1 {
				declAt = locs[0][0]
			}
			// Cut every copy out so the scan below sees what is left;
			// extra copies are reported through total.
			c = c[:locs[0][0]] + c[locs[0][1]:]
			for len(wantLineRe.FindStringIndex(c)) > 0 {
				l := wantLineRe.FindStringIndex(c)
				c = c[:l[0]] + c[l[1]:]
			}
		}
		code[p.name] = c
	}
	switch {
	case total == 0:
		errs = append(errs, fmt.Errorf("no partial contains the exact definition line %q at column 0 — esc must be declared once, verbatim (a changed or removed escaper is a portal-wide XSS regression; if the change is intended, update escWantLine and say why)", escWantLine))
	case total > 1:
		errs = append(errs, fmt.Errorf("the definition line of esc appears %d times across the partials, want exactly 1", total))
	}

	for _, p := range parts {
		c := code[p.name]
		for _, re := range []*regexp.Regexp{escDeclRe, escWriteRe} {
			for _, m := range re.FindAllString(c, -1) {
				errs = append(errs, fmt.Errorf("%s: found %q — esc must be declared once, as the pinned const line, and never redeclared or reassigned (a local copy shadows the shared one; a write swaps it for every pane)", p.name, strings.TrimSpace(m)))
			}
		}
	}

	if total != 1 {
		return errors.Join(errs...)
	}
	if !escIsFirstStatement(stripEscComments(partialBody(parts, definer)), declAt) {
		errs = append(errs, fmt.Errorf("%s: the esc declaration is not the first statement of its <script> — code before it is either wrapping it in an IIFE/function/block (private to that scope) or can throw before the const is initialised, which leaves esc in its TDZ for every pane", definer))
	}

	order, err := rootCallOrder(fsys)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	pos := map[string]int{}
	for i, name := range order {
		if _, seen := pos[name]; !seen {
			pos[name] = i
		}
	}
	dp, ok := pos[definer]
	if !ok {
		return errors.Join(append(errs, fmt.Errorf("%s declares esc but the root does not call it at its top level", definer))...)
	}
	for _, p := range parts {
		switch {
		case p.name == definer:
			continue
		case p.name == portalRootTmpl:
			// The root's own inline script: whatever sits before the
			// definer's call is served before esc exists.
			rc := code[p.name]
			callRe := regexp.MustCompile(`\{\{-?\s*template\s+"` + regexp.QuoteMeta(definer) + `"`)
			if loc := callRe.FindStringIndex(rc); loc != nil && escUseRe.MatchString(rc[:loc[0]]) {
				errs = append(errs, fmt.Errorf("%s uses esc in its inline script before it calls %s, which declares it — that use would be a ReferenceError", p.name, definer))
			}
			continue
		}
		up, ok := pos[p.name]
		if !ok {
			continue // reported by checkPortalAssembly
		}
		if up < dp && escUseRe.MatchString(code[p.name]) {
			errs = append(errs, fmt.Errorf("%s uses esc but is served BEFORE %s, which declares it — that use would be a ReferenceError", p.name, definer))
		}
	}
	return errors.Join(errs...)
}

// partialBody returns the body of the named partial.
func partialBody(parts []portalPartial, name string) string {
	for _, p := range parts {
		if p.name == name {
			return p.body
		}
	}
	return ""
}

// TestPortalPartials_RootCallsEveryPartialExactlyOnce runs the assembly
// contract (checkPortalAssembly's doc lists exactly what is guaranteed)
// against the embedded partials.
func TestPortalPartials_RootCallsEveryPartialExactlyOnce(t *testing.T) {
	if err := checkPortalAssembly(portalFS); err != nil {
		t.Error(err)
	}
}

// TestPortalPartials_ScriptAndStyleBlocksAreWholeAndNonced runs
// checkPortalScriptAndStyle against the embedded partials. The
// rendered-output nonce test (csp_test.go) sees only the assembled document;
// this one names the offending file.
func TestPortalPartials_ScriptAndStyleBlocksAreWholeAndNonced(t *testing.T) {
	if err := checkPortalScriptAndStyle(portalFS); err != nil {
		t.Error(err)
	}
}

// TestPortalPartials_EscDefinedOnceBeforePanes runs checkPortalEsc against the
// embedded partials.
func TestPortalPartials_EscDefinedOnceBeforePanes(t *testing.T) {
	if err := checkPortalEsc(portalFS); err != nil {
		t.Error(err)
	}
}

// TestPortalPartials_CountWithinSignpost enforces the architect's bound
// (REFACTORING.md P28 §9: "partial が 15 を超える" is a signal to revisit
// the split-source/single-document decision, not something to drift past).
func TestPortalPartials_CountWithinSignpost(t *testing.T) {
	const maxPartials = 15
	if n := len(portalPartials(t)); n > maxPartials {
		t.Errorf("%d portal partials, want <= %d — past this the P28 §9 design says to revisit the layout (see REFACTORING.md) rather than keep adding files", n, maxPartials)
	}
}

// mutatedPortalFS copies the real embedded partials into an in-memory FS and
// applies mutate to it, so a negative test changes exactly one thing about
// the real file set without touching the files.
func mutatedPortalFS(t *testing.T, mutate func(t *testing.T, m fstest.MapFS)) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	dir := path.Dir(portalTmplGlob)
	for _, p := range portalPartials(t) {
		m[dir+"/"+p.name] = &fstest.MapFile{Data: []byte(p.body)}
	}
	mutate(t, m)
	return m
}

// portalFSEdit returns a mutation that rewrites one partial's source. It
// fails the test if the rewrite changed nothing, so a mutation cannot go
// stale (and its negative test vacuous) when the real file is later edited.
func portalFSEdit(name string, edit func(string) string) func(*testing.T, fstest.MapFS) {
	return func(t *testing.T, m fstest.MapFS) {
		t.Helper()
		key := path.Dir(portalTmplGlob) + "/" + name
		f, ok := m[key]
		if !ok {
			t.Fatalf("mutation targets %s, which is not a partial", key)
		}
		before := string(f.Data)
		after := edit(before)
		if after == before {
			t.Fatalf("mutation of %s changed nothing — the text it rewrites is no longer in the file", name)
		}
		m[key] = &fstest.MapFile{Data: []byte(after)}
	}
}

func replaceOnce(old, new string) func(string) string {
	return func(s string) string { return strings.Replace(s, old, new, 1) }
}

func appendText(extra string) func(string) string {
	return func(s string) string { return s + extra }
}

func prependText(extra string) func(string) string {
	return func(s string) string { return extra + s }
}

// TestPortalPartials_ChecksRejectMutations is the proof that the three checks
// above (checkPortalAssembly, checkPortalScriptAndStyle, checkPortalEsc) can
// fail: each case applies ONE mutation to a copy of the real partials and
// requires the named check to report it. The unmutated copy must pass all
// three, so a failure here is the mutation and not the copy.
//
// Cases 1-3 are mutations review found passing every test while changing
// what is served (they hid behind `{{ ` spacing from the earlier
// text-counting version of the assembly check).
func TestPortalPartials_ChecksRejectMutations(t *testing.T) {
	clean := mutatedPortalFS(t, func(*testing.T, fstest.MapFS) {})
	if err := checkPortalAssembly(clean); err != nil {
		t.Fatalf("unmutated copy fails checkPortalAssembly: %v", err)
	}
	if err := checkPortalScriptAndStyle(clean); err != nil {
		t.Fatalf("unmutated copy fails checkPortalScriptAndStyle: %v", err)
	}
	if err := checkPortalEsc(clean); err != nil {
		t.Fatalf("unmutated copy fails checkPortalEsc: %v", err)
	}

	const homeCall = `{{template "pane-home.tmpl" . -}}`
	cases := []struct {
		name    string
		mutate  func(*testing.T, fstest.MapFS)
		check   func(fs.FS) error
		wantErr string
	}{
		{
			name:    "root calls a partial a second time, spaced action",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, homeCall+"\n"+`{{ template "pane-home.tmpl" . -}}`)),
			check:   checkPortalAssembly,
			wantErr: "partial pane-home.tmpl is called 2 time(s)",
		},
		{
			name:    "non-root partial calls a template, spaced action",
			mutate:  portalFSEdit("pane-me.tmpl", appendText(`{{ template "css.tmpl" . }}`+"\n")),
			check:   checkPortalAssembly,
			wantErr: `pane-me.tmpl calls template "css.tmpl"`,
		},
		{
			name:    "later file redefines another partial's name",
			mutate:  portalFSEdit("pane-tutorial.tmpl", appendText(`{{ define "pane-home.tmpl" }}<p>swapped</p>{{ end }}`+"\n")),
			check:   checkPortalAssembly,
			wantErr: `pane-tutorial.tmpl defines template(s) ["pane-home.tmpl" "pane-tutorial.tmpl"]`,
		},
		{
			name:    "block in the root",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, homeCall+"\n"+`{{block "extra" .}}x{{end}}`)),
			check:   checkPortalAssembly,
			wantErr: `portal.tmpl defines template(s) ["extra" "portal.tmpl"]`,
		},
		{
			name: "router moved ahead of the panes",
			mutate: portalFSEdit(portalRootTmpl, func(s string) string {
				const router = `{{template "core-router.tmpl" . -}}` + "\n"
				const story = `{{template "pane-story.tmpl" . -}}` + "\n"
				return strings.Replace(strings.Replace(s, router, "", 1), story, router+story, 1)
			}),
			check:   checkPortalAssembly,
			wantErr: `last {{template}} call is "pane-terminal.tmpl", want "core-router.tmpl"`,
		},
		{
			name: "pane moved after the router",
			mutate: portalFSEdit(portalRootTmpl, func(s string) string {
				const router = `{{template "core-router.tmpl" . -}}` + "\n"
				return strings.Replace(strings.Replace(s, homeCall+"\n", "", 1), router, router+homeCall+"\n", 1)
			}),
			check:   checkPortalAssembly,
			wantErr: `last {{template}} call is "pane-home.tmpl", want "core-router.tmpl"`,
		},
		{
			name:    "define adds a name no file has",
			mutate:  portalFSEdit("pane-me.tmpl", appendText(`{{define "helper"}}x{{end}}`+"\n")),
			check:   checkPortalAssembly,
			wantErr: `but the partial files are`,
		},
		{
			name:    "partial never called",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall+"\n", "")),
			check:   checkPortalAssembly,
			wantErr: "partial pane-home.tmpl is called 0 time(s)",
		},
		{
			name:    "call without dot",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, `{{template "pane-home.tmpl" -}}`)),
			check:   checkPortalAssembly,
			wantErr: `calls "pane-home.tmpl" without`,
		},
		{
			name:    "call with a non-dot argument",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, `{{template "pane-home.tmpl" .Nonce -}}`)),
			check:   checkPortalAssembly,
			wantErr: `calls "pane-home.tmpl" without`,
		},
		{
			name:    "call to a name with no file",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, `{{template "pane-nope.tmpl" . -}}`)),
			check:   checkPortalAssembly,
			wantErr: `calls "pane-nope.tmpl", which is not a partial file`,
		},
		{
			name:    "second call nested under if",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, homeCall+"\n"+`{{if .Nonce}}{{template "pane-home.tmpl" .}}{{end}}`)),
			check:   checkPortalAssembly,
			wantErr: `portal.tmpl calls "pane-home.tmpl" inside {{if}}/{{range}}/{{with}}`,
		},
		{
			name:    "only call wrapped in if false (pane never served)",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, `{{ if false }}{{ template "pane-home.tmpl" . }}{{ end }}`)),
			check:   checkPortalAssembly,
			wantErr: `portal.tmpl calls "pane-home.tmpl" inside {{if}}/{{range}}/{{with}}`,
		},
		{
			name:    "only call wrapped in if .Nonce (served depending on data)",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(`{{template "pane-tutorial.tmpl" . -}}`, `{{ if .Nonce }}{{ template "pane-tutorial.tmpl" . }}{{ end }}`)),
			check:   checkPortalAssembly,
			wantErr: `portal.tmpl calls "pane-tutorial.tmpl" inside {{if}}/{{range}}/{{with}}`,
		},
		{
			name:    "only call wrapped in range (served N times)",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, `{{range .Nonce}}{{template "pane-home.tmpl" $ -}}{{end}}`)),
			check:   checkPortalAssembly,
			wantErr: `portal.tmpl calls "pane-home.tmpl" inside {{if}}/{{range}}/{{with}}`,
		},
		{
			name:    "only call wrapped in with, else branch",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, `{{with .Nonce}}x{{else}}{{template "pane-home.tmpl" .}}{{end}}`)),
			check:   checkPortalAssembly,
			wantErr: `portal.tmpl calls "pane-home.tmpl" inside {{if}}/{{range}}/{{with}}`,
		},
		{
			name: "root shell missing",
			mutate: func(_ *testing.T, m fstest.MapFS) {
				delete(m, path.Dir(portalTmplGlob)+"/"+portalRootTmpl)
			},
			check:   checkPortalAssembly,
			wantErr: "root shell portal.tmpl is not among the partials",
		},
		{
			name: "no partials at all",
			mutate: func(_ *testing.T, m fstest.MapFS) {
				for k := range m {
					delete(m, k)
				}
			},
			check:   checkPortalAssembly,
			wantErr: "no portal partials match",
		},
		// ---- esc: the pinned escaper body ----
		{
			name:    "esc body: the .replace is cut out",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(`.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))`, "")),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		{
			name:    "esc body: \"' dropped from the character class",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(`/[&<>"']/g`, `/[&<>]/g`)),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		{
			name:    "esc body: the &#39; entity is replaced",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(`'&#39;'`, `"'"`)),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		{
			name:    "esc body: null-safety removed",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(`String(s == null ? '' : s)`, `String(s)`)),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		{
			name:    "esc declaration renamed away (no definition at all)",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce("const esc =", "const escape2 =")),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		{
			name:    "esc declaration is a function, not the pinned const",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "function esc(s) { return String(s); }")),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		// ---- esc: a second declaration, in every spelling ----
		{
			name:    "pane redeclares esc (function, indented in the IIFE)",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  function esc(s) { return String(s); }\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane redeclares esc (async function)",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  async function esc(s) { return String(s); }\n")),
			check:   checkPortalEsc,
			wantErr: `found "function esc"`,
		},
		{
			name:    "pane redeclares esc (const arrow)",
			mutate:  portalFSEdit("pane-board.tmpl", replaceOnce("(function () {\n", "(function () {\n  const esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane redeclares esc (let)",
			mutate:  portalFSEdit("pane-board.tmpl", replaceOnce("(function () {\n", "(function () {\n  let esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: `found "let esc`,
		},
		{
			name:    "pane redeclares esc (var)",
			mutate:  portalFSEdit("pane-story.tmpl", replaceOnce("(function () {\n", "(function () {\n  var esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: `found "var esc`,
		},
		{
			name:    "pane redeclares esc mid-line after a semicolon",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  let z = 0; const esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane redeclares esc in a comma-separated declaration",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  const fmt = x => x, esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane destructures esc",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  const { esc } = helpers;\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "the declaration line is duplicated in core-util",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, escWantLine+"\n"+escWantLine)),
			check:   checkPortalEsc,
			wantErr: "appears 2 times",
		},
		{
			name:    "the declaration line is copied into a second partial",
			mutate:  portalFSEdit("pane-home.tmpl", appendText("<script nonce=\"{{.Nonce}}\">\n"+escWantLine+"\n</script>\n")),
			check:   checkPortalEsc,
			wantErr: "appears 2 times",
		},
		{
			name:    "the pinned line is not at column 0 (indented)",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "  "+escWantLine)),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		{
			name:    "the pinned line follows other code on its line",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "let z = 0; "+escWantLine)),
			check:   checkPortalEsc,
			wantErr: "no partial contains the exact definition line",
		},
		// ---- esc: reassignment / swap, in every spelling ----
		{
			name:    "pane reassigns esc (bare)",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  esc = s => s;\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane reassigns esc (function expression, no space)",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  esc=function (s) { return s; };\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane reassigns esc mid-line",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  if (x) { esc = s => s; }\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane reassigns esc (compound ||=)",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  esc ||= s => s;\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane assigns window.esc",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  window.esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane assigns self.esc",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  self.esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane assigns globalThis.esc",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  globalThis.esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane assigns window['esc']",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  window['esc'] = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane Object.defineProperty(window, 'esc', ...)",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  Object.defineProperty(window, 'esc', { value: s => s });\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "pane Reflect.set(window, 'esc', ...)",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  Reflect.set(window, \"esc\", s => s);\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		{
			name:    "core-util itself reassigns esc after declaring it",
			mutate:  portalFSEdit("core-util.tmpl", appendText("<script nonce=\"{{.Nonce}}\">\nesc = s => s;\n</script>\n")),
			check:   checkPortalEsc,
			wantErr: "never redeclared or reassigned",
		},
		// ---- esc: top level, and served before every use ----
		{
			name:    "shared declaration wrapped in an IIFE (private to that script)",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "(function () {\n"+escWantLine+"\n})();")),
			check:   checkPortalEsc,
			wantErr: "not the first statement of its <script>",
		},
		{
			name:    "shared declaration inside a block",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "if (true) {\n"+escWantLine+"\n}")),
			check:   checkPortalEsc,
			wantErr: "not the first statement of its <script>",
		},
		{
			name:    "a statement that can throw precedes the declaration (TDZ)",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "document.getElementById('no-such-id').textContent = 'x';\n"+escWantLine)),
			check:   checkPortalEsc,
			wantErr: "not the first statement of its <script>",
		},
		{
			name:    "a helper statement precedes the declaration",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, "const fmt = (n) => String(n);\n"+escWantLine)),
			check:   checkPortalEsc,
			wantErr: "not the first statement of its <script>",
		},
		{
			name: "shared declaration served after the panes that use it",
			mutate: portalFSEdit(portalRootTmpl, func(s string) string {
				const util = `{{template "core-util.tmpl" . -}}` + "\n"
				const router = `{{template "core-router.tmpl" . -}}` + "\n"
				return strings.Replace(strings.Replace(s, util, "", 1), router, util+router, 1)
			}),
			check:   checkPortalEsc,
			wantErr: "pane-story.tmpl uses esc but is served BEFORE core-util.tmpl",
		},
		{
			name: "declaration moved from core-util into a later pane (top level of its script)",
			mutate: func(t *testing.T, m fstest.MapFS) {
				portalFSEdit("core-util.tmpl", replaceOnce(escWantLine, ""))(t, m)
				portalFSEdit("pane-terminal.tmpl", replaceOnce("<script nonce=\"{{.Nonce}}\">\n", "<script nonce=\"{{.Nonce}}\">\n"+escWantLine+"\n"))(t, m)
			},
			check:   checkPortalEsc,
			wantErr: "pane-story.tmpl uses esc but is served BEFORE pane-terminal.tmpl",
		},
		{
			name:    "the root does not call the partial that declares esc",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(`{{template "core-util.tmpl" . -}}`+"\n", "")),
			check:   checkPortalEsc,
			wantErr: "core-util.tmpl declares esc but the root does not call it",
		},
		{
			name:    "the root's own inline script uses esc before the declaring call",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(`{{template "core-util.tmpl" . -}}`, "<script nonce=\"{{.Nonce}}\">\ndocument.title = esc(window.__PORTAL_USER__);\n</script>\n{{template \"core-util.tmpl\" . -}}")),
			check:   checkPortalEsc,
			wantErr: "portal.tmpl uses esc in its inline script before it calls core-util.tmpl",
		},
		{
			name: "a pane that only passes esc by reference is served before the declaration",
			mutate: func(t *testing.T, m fstest.MapFS) {
				const util = `{{template "core-util.tmpl" . -}}` + "\n"
				const terminal = `{{template "pane-terminal.tmpl" . -}}`
				portalFSEdit(portalRootTmpl, func(s string) string {
					return strings.Replace(strings.Replace(s, util, "", 1), terminal, util+terminal, 1)
				})(t, m)
				portalFSEdit("pane-home.tmpl", appendText("<script nonce=\"{{.Nonce}}\">\n[1].map(esc);\n</script>\n"))(t, m)
			},
			check:   checkPortalEsc,
			wantErr: "pane-home.tmpl uses esc but is served BEFORE core-util.tmpl",
		},
		{
			name:    "script without nonce",
			mutate:  portalFSEdit("pane-home.tmpl", appendText("<script>\nx();\n</script>\n")),
			check:   checkPortalScriptAndStyle,
			wantErr: `pane-home.tmpl: script open tag "<script>"`,
		},
		{
			name:    "uppercase script without nonce",
			mutate:  portalFSEdit("pane-home.tmpl", appendText("<SCRIPT>\nx();\n</SCRIPT>\n")),
			check:   checkPortalScriptAndStyle,
			wantErr: `pane-home.tmpl: script open tag "<SCRIPT>"`,
		},
		{
			name:    "indented script the line-start scan cannot see",
			mutate:  portalFSEdit("pane-home.tmpl", appendText("  <script>x();</script>\n")),
			check:   checkPortalScriptAndStyle,
			wantErr: "a script tag is served that the source scan does not cover",
		},
		{
			name:    "indented style the line-start scan cannot see",
			mutate:  portalFSEdit("pane-home.tmpl", appendText("  <STYLE>.x{}</STYLE>\n")),
			check:   checkPortalScriptAndStyle,
			wantErr: "a style tag is served that the source scan does not cover",
		},
		{
			name: "script block straddles two partials",
			mutate: func(t *testing.T, m fstest.MapFS) {
				portalFSEdit("pane-home.tmpl", appendText("<script nonce=\"{{.Nonce}}\">\n"))(t, m)
				portalFSEdit("pane-tutorial.tmpl", prependText("x();\n</script>\n"))(t, m)
			},
			check:   checkPortalScriptAndStyle,
			wantErr: "pane-home.tmpl: 1 <script> open tag(s) but 0 </script>",
		},
		{
			name:    "style block left open in a partial",
			mutate:  portalFSEdit("pane-home.tmpl", appendText("<style>\n.x{}\n")),
			check:   checkPortalScriptAndStyle,
			wantErr: "pane-home.tmpl: 1 <style> open tag(s) but 0 </style>",
		},
		{
			name:    "duplicate call doubles a served style block",
			mutate:  portalFSEdit(portalRootTmpl, replaceOnce(homeCall, homeCall+"\n"+`{{ template "css.tmpl" . }}`)),
			check:   checkPortalScriptAndStyle,
			wantErr: "a style tag is served that the source scan does not cover",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.check(mutatedPortalFS(t, tc.mutate))
			if err == nil {
				t.Fatalf("check passed a mutated partial set; want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("check failed, but not for the mutation under test.\n got: %v\nwant substring: %q", err, tc.wantErr)
			}
		})
	}
}
