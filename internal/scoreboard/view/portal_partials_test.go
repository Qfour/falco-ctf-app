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
// those nested under if/range/with.
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
//  2. The root calls every other partial exactly once, with `.` as the
//     argument (without it the partial sees no data: every {{.Nonce}}
//     renders empty and CSP blocks that script), and calls nothing that is
//     not a partial. Uncalled = passes the source gates but is never served;
//     called twice = duplicate element ids.
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
			for _, c := range templateCalls(tree.Root) {
				if p.name != portalRootTmpl || name != portalRootTmpl {
					errs = append(errs, fmt.Errorf("%s calls template %q — only the root %s composes partials (flat layout)", p.name, c.Name, portalRootTmpl))
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
			wantErr: "partial pane-home.tmpl is called 2 time(s)",
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
