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
// partial adds its own rule to checkPortalAssembly.
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
	if err := tmpl.Execute(&buf, portalData{Nonce: "test-nonce"}); err != nil {
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

var (
	// A definition of esc in any of the forms a pane could plausibly use:
	// `function esc`, `const|let|var esc`, and a property assignment
	// `window.esc = ` / `globalThis.esc = `. Matched at line start (after
	// indentation) so a prose mention inside a `//` comment is not a
	// definition. A second definition under another spelling (`esc = ...`
	// without a keyword) is not matched; the call-order half of the check and
	// code review cover that.
	escDefRe = regexp.MustCompile(`(?m)^[ \t]*(?:function[ \t]+esc\b|(?:const|let|var)[ \t]+esc\b|(?:window|globalThis)\.esc[ \t]*=)`)
	// Any mention of esc( — comments included, deliberately: a partial that
	// only mentions it in prose is still required to come after the
	// definition, which costs nothing and keeps the rule free of a
	// comment-stripper.
	escUseRe = regexp.MustCompile(`\besc\(`)
	// A line-start IIFE opener. The shared esc must be a top-level
	// declaration so other partials' scripts can reach it; inside an IIFE it
	// would be private to that one script.
	iifeOpenRe = regexp.MustCompile(`(?m)^\((?:function\b|async\b|\(\)[ \t]*=>)`)
)

// rootCallOrder returns the names the root calls at its top level, in
// document order (the order html/template serves them).
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

// checkPortalEsc verifies the single-escape-path rule (P28-0a): the portal
// has exactly ONE definition of esc across all partials; it is a top-level
// (non-IIFE) declaration; and the partial holding it is called by the root
// before every other partial that uses esc(. A second definition is a
// shadow that can drift from the first (the five panes once carried five
// copies, two of them with a different null behaviour); a definition served
// after a pane's script is a ReferenceError at that pane's first render,
// which no Go test would otherwise see.
func checkPortalEsc(fsys fs.FS) error {
	parts, err := readPortalPartials(fsys)
	if err != nil {
		return err
	}
	var errs []error
	definer := ""
	defs := 0
	for _, p := range parts {
		n := len(escDefRe.FindAllString(p.body, -1))
		if n == 0 {
			continue
		}
		defs += n
		definer = p.name
		if n > 1 {
			errs = append(errs, fmt.Errorf("%s defines esc %d times, want exactly one definition across all partials", p.name, n))
		}
		if iifeOpenRe.MatchString(p.body) {
			errs = append(errs, fmt.Errorf("%s defines esc but also opens an IIFE at line start — the shared esc must be a top-level declaration, or other partials' scripts cannot reach it", p.name))
		}
	}
	switch {
	case defs == 0:
		return errors.Join(append(errs, errors.New("no partial defines esc — every pane's innerHTML escaping would be a ReferenceError"))...)
	case defs > 1:
		var who []string
		for _, p := range parts {
			if escDefRe.MatchString(p.body) {
				who = append(who, p.name)
			}
		}
		errs = append(errs, fmt.Errorf("esc is defined %d times (in %v), want exactly one — a local copy shadows the shared one and can drift from it", defs, who))
		return errors.Join(errs...)
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
		return errors.Join(append(errs, fmt.Errorf("%s defines esc but the root does not call it at its top level", definer))...)
	}
	for _, p := range parts {
		if p.name == definer || p.name == portalRootTmpl || !escUseRe.MatchString(p.body) {
			continue
		}
		up, ok := pos[p.name]
		if !ok {
			continue // reported by checkPortalAssembly
		}
		if up < dp {
			errs = append(errs, fmt.Errorf("%s uses esc( but is served BEFORE %s, which defines it — the call would fail with a ReferenceError", p.name, definer))
		}
	}
	return errors.Join(errs...)
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

// TestPortalPartials_ChecksRejectMutations is the proof that the two checks
// above can fail: each case applies ONE mutation to a copy of the real
// partials and requires the named check to report it. The unmutated copy
// must pass both, so a failure here is the mutation and not the copy.
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
		{
			name:    "a pane redefines esc locally (function)",
			mutate:  portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  function esc(s) { return String(s); }\n")),
			check:   checkPortalEsc,
			wantErr: "esc is defined 2 times",
		},
		{
			name:    "a pane redefines esc locally (const arrow)",
			mutate:  portalFSEdit("pane-board.tmpl", replaceOnce("(function () {\n", "(function () {\n  const esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "esc is defined 2 times",
		},
		{
			name:    "a pane assigns window.esc",
			mutate:  portalFSEdit("pane-terminal.tmpl", replaceOnce("(function () {\n", "(function () {\n  window.esc = s => String(s);\n")),
			check:   checkPortalEsc,
			wantErr: "esc is defined 2 times",
		},
		{
			name:    "the shared definition is removed",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce("function esc(s)", "function escape2(s)")),
			check:   checkPortalEsc,
			wantErr: "no partial defines esc",
		},
		{
			name: "shared definition served after the panes that use it",
			mutate: portalFSEdit(portalRootTmpl, func(s string) string {
				const util = `{{template "core-util.tmpl" . -}}` + "\n"
				const router = `{{template "core-router.tmpl" . -}}` + "\n"
				return strings.Replace(strings.Replace(s, util, "", 1), router, util+router, 1)
			}),
			check:   checkPortalEsc,
			wantErr: "uses esc( but is served BEFORE core-util.tmpl",
		},
		{
			name:    "shared definition wrapped in an IIFE (private to that script)",
			mutate:  portalFSEdit("core-util.tmpl", replaceOnce("  function esc(s)", "(function () {\n  function esc(s)")),
			check:   checkPortalEsc,
			wantErr: "opens an IIFE at line start",
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
