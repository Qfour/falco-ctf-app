package view

import (
	"bytes"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// portalPartial is one embedded templates/portal/*.tmpl source file.
type portalPartial struct {
	name string // basename == html/template name
	body string
}

// portalPartials returns every embedded portal partial, sorted by name. It
// is the ONE way a test should get at the portal's template source (P28-0a):
// a source-level gate that names files individually silently stops covering
// a partial added later, and one that tolerates an empty list is green
// forever. So this fails the calling test outright when it finds nothing,
// and when the root shell is not among what it found.
func portalPartials(t *testing.T) []portalPartial {
	t.Helper()
	names, err := fs.Glob(portalFS, portalTmplGlob)
	if err != nil {
		t.Fatalf("glob %s: %v", portalTmplGlob, err)
	}
	if len(names) == 0 {
		t.Fatalf("no portal partials match %s — every source-level gate over the portal would be scanning nothing", portalTmplGlob)
	}
	sort.Strings(names)
	out := make([]portalPartial, 0, len(names))
	hasRoot := false
	for _, n := range names {
		b, err := fs.ReadFile(portalFS, n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		if len(b) == 0 {
			t.Fatalf("%s is empty", n)
		}
		base := path.Base(n)
		hasRoot = hasRoot || base == portalRootTmpl
		out = append(out, portalPartial{name: base, body: string(b)})
	}
	if !hasRoot {
		t.Fatalf("root shell %s is not among the embedded partials %v", portalRootTmpl, names)
	}
	return out
}

// portalTemplateCallRe matches the only form a partial may be called in:
// alone on its line, with `.` (so portalData — the nonce above all — reaches
// it) and a trailing trim marker (so the call line's own newline is not
// emitted). See portalFS's doc in view.go.
var portalTemplateCallRe = regexp.MustCompile(`(?m)^\{\{template "([^"]+)" \. -\}\}$`)

// TestPortalPartials_RootCallsEveryPartialExactlyOnce pins the assembly
// contract the split relies on. html/template reports a {{template}} call to
// a missing name only on first Execute, and reports an embedded-but-uncalled
// partial never, so neither would be caught at init:
//   - a call to a name with no file      → GET /portal 500s
//   - a partial no call reaches          → it passes the source gates (hex
//     scan) while never being served, or a pane silently disappears
//   - a partial called twice             → duplicate element ids / listeners
//   - a call written in any other form   → data not passed (`{{template
//     "x"}}` renders every {{.Nonce}} empty, and CSP then blocks that
//     script) or a stray newline
//   - a call from a non-root partial     → nesting the flat layout
func TestPortalPartials_RootCallsEveryPartialExactlyOnce(t *testing.T) {
	parts := portalPartials(t)
	calls := map[string]int{}
	for _, p := range parts {
		anyCall := strings.Count(p.body, "{{template") + strings.Count(p.body, "{{- template") + strings.Count(p.body, "{{define") + strings.Count(p.body, "{{- define") + strings.Count(p.body, "{{block") + strings.Count(p.body, "{{- block")
		strict := portalTemplateCallRe.FindAllStringSubmatch(p.body, -1)
		if p.name != portalRootTmpl {
			if anyCall != 0 {
				t.Errorf("%s contains %d {{template}}/{{define}}/{{block}} action(s) — only the root %s composes partials (flat layout)", p.name, anyCall, portalRootTmpl)
			}
			continue
		}
		if anyCall != len(strict) {
			t.Errorf("%s has %d {{template}}/{{define}}/{{block}} action(s) but only %d in the required form `{{template \"x.tmpl\" . -}}` alone on a line", p.name, anyCall, len(strict))
		}
		for _, m := range strict {
			calls[m[1]]++
		}
	}
	if len(calls) == 0 {
		t.Fatalf("root %s calls no partial at all", portalRootTmpl)
	}
	have := map[string]bool{}
	for _, p := range parts {
		have[p.name] = true
		if p.name == portalRootTmpl {
			if calls[p.name] != 0 {
				t.Errorf("root %s calls itself", p.name)
			}
			continue
		}
		if got := calls[p.name]; got != 1 {
			t.Errorf("partial %s is called %d time(s) from %s, want exactly 1", p.name, got, portalRootTmpl)
		}
	}
	for name := range calls {
		if !have[name] {
			t.Errorf("root %s calls %q, which is not an embedded partial", portalRootTmpl, name)
		}
		if portalTmpl.Lookup(name) == nil {
			t.Errorf("root %s calls %q, which portalTmpl does not define", portalRootTmpl, name)
		}
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

// TestPortalPartials_ScriptAndStyleBlocksAreWholeAndNonced checks, per
// partial and at SOURCE level, that no <script>/<style> element straddles a
// partial boundary and that every <script> open tag carries the nonce. The
// rendered-output nonce tests (csp_test.go) see only the assembled document;
// this one names the offending file, and catches a cut made mid-element
// (which would shift html/template's escaping context across the boundary).
//
// Open/close tags are matched at line start: that is how every real one is
// written in these files, and it keeps prose mentions inside comments and JS
// strings ("a future inline <script> ...") out of the count.
func TestPortalPartials_ScriptAndStyleBlocksAreWholeAndNonced(t *testing.T) {
	scriptOpen := regexp.MustCompile(`(?m)^<script\b[^>]*>`)
	scriptClose := regexp.MustCompile(`(?m)^</script>`)
	styleOpen := regexp.MustCompile(`(?m)^<style\b[^>]*>`)
	styleClose := regexp.MustCompile(`(?m)^</style>`)
	const wantOpen = `<script nonce="{{.Nonce}}">`
	totalScripts := 0
	for _, p := range portalPartials(t) {
		opens := scriptOpen.FindAllString(p.body, -1)
		if c := len(scriptClose.FindAllString(p.body, -1)); c != len(opens) {
			t.Errorf("%s: %d <script> open tag(s) but %d </script> — a script block must not straddle partials", p.name, len(opens), c)
		}
		if o, c := len(styleOpen.FindAllString(p.body, -1)), len(styleClose.FindAllString(p.body, -1)); o != c {
			t.Errorf("%s: %d <style> open tag(s) but %d </style> — a style block must not straddle partials", p.name, o, c)
		}
		for _, o := range opens {
			if o != wantOpen {
				t.Errorf("%s: script open tag %q, want exactly %q (CSP script-src is nonce-only; an un-nonced inline script is silently blocked)", p.name, o, wantOpen)
			}
		}
		totalScripts += len(opens)
	}
	if totalScripts == 0 {
		t.Fatal("found no <script> open tag in any portal partial — the line-start matcher no longer matches how these files are written, so this test is checking nothing")
	}

	// Cross-check the source count against what is actually served, so a
	// script the line-start matcher cannot see (indented, or produced by a
	// partial this test did not scan) fails here instead of going unchecked.
	var buf bytes.Buffer
	if err := portalTmpl.Execute(&buf, portalData{Nonce: "test-nonce"}); err != nil {
		t.Fatalf("execute portal: %v", err)
	}
	rendered := len(regexp.MustCompile(`<script\b`).FindAllString(buf.String(), -1))
	if rendered != totalScripts {
		t.Errorf("rendered portal has %d <script> tag(s) but the partials' line-start open tags total %d — a script tag exists that this test's source scan does not cover", rendered, totalScripts)
	}
}
