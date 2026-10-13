package view

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// P28-0a (4), app#285: the tablist / live-region wiring. Source-text checks on
// the rendered document and the router partial. No test executes the page's
// JS (make test runs in Dockerfile.test, which has no JS engine), so the
// keyboard behavior is pinned as source text (tablistPins) until the ADR-0031
// browser harness exists; it is also a manual check in the PR.

// TestPortal_TablistWiring: every tab has a matching tab link and pane, the
// tab links sit in a role=tablist, and the one live region exists. The pane
// ids come from PORTAL_TABS in the router, so a new pane that forgets its tab
// link (or the reverse) fails here.
func TestPortal_TablistWiring(t *testing.T) {
	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	if err := renderPortal(w, r, nil, nil, ""); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}
	body := w.Body.String()

	router := partialBody(portalPartials(t), "core-router.tmpl")
	pt := regexp.MustCompile(`const PORTAL_TABS = \[([^\]]*)\]`).FindStringSubmatch(router)
	if pt == nil {
		t.Fatal("PORTAL_TABS not found in core-router.tmpl")
	}
	ids := regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(pt[1], -1)
	if len(ids) == 0 {
		t.Fatal("PORTAL_TABS is empty")
	}
	if !regexp.MustCompile(`<div id="portal-tablist" role="tablist"`).MatchString(body) {
		t.Error("the tab links are not inside a role=tablist")
	}
	for _, id := range ids {
		tab := id[1]
		link := regexp.MustCompile(`<a [^>]*\bid="tab-` + tab + `"[^>]*>`).FindString(body)
		if link == "" {
			t.Errorf("no tab link with id=\"tab-%s\"", tab)
			continue
		}
		for _, want := range []string{`role="tab"`, `aria-controls="pane-` + tab + `"`, `aria-selected=`, `data-tab="` + tab + `"`} {
			if !strings.Contains(link, want) {
				t.Errorf("tab link %q lacks %s", link, want)
			}
		}
		if !strings.Contains(body, `id="pane-`+tab+`"`) {
			t.Errorf("tab %q has no element id=\"pane-%s\"", tab, tab)
		}
	}
	// The CALL, not the definition: a line that is just `wireTabpanels();`.
	if !regexp.MustCompile(`(?m)^\s*wireTabpanels\(\);`).MatchString(router) || !strings.Contains(router, "role', 'tabpanel'") {
		t.Error("the router no longer gives each pane role=tabpanel")
	}
	if !regexp.MustCompile(`(?m)^\s*wireTablistKeys\(\);`).MatchString(router) {
		t.Error("the router no longer wires the tablist arrow-key handler")
	}
	if !regexp.MustCompile(`<div id="portal-live"[^>]*role="status"[^>]*aria-live="polite"`).MatchString(body) {
		t.Error("the portal has no polite live region #portal-live")
	}
}

// jsFuncBody returns the body of `function name(...) { ... }` in code, or ""
// when there is none. Braces inside string and template literals are skipped.
func jsFuncBody(code, name string) string {
	loc := regexp.MustCompile(`\bfunction\s+` + regexp.QuoteMeta(name) + `\s*\([^)]*\)\s*\{`).FindStringIndex(code)
	if loc == nil {
		return ""
	}
	depth := 0
	for i := loc[1] - 1; i < len(code); i++ {
		switch c := code[i]; c {
		case '\'', '"', '`':
			for j := i + 1; j < len(code); j++ {
				if code[j] == '\\' {
					j++
				} else if code[j] == c {
					i = j
					break
				}
			}
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return code[loc[1]:i]
			}
		}
	}
	return ""
}

// tablistPins is the tablist keyboard model (WAI-ARIA tabs, automatic
// activation) as source text, each pattern scoped to the function that must
// hold it. A stand-in for the ADR-0031 harness (review-5x T2 R2#6): without
// it, deleting the roving tabindex, the aria-selected update or an arrow-key
// branch failed no test. Whitespace inside a pattern is free; the expression
// is not. Changing the behavior means changing the pin, in a commit that says
// why.
var tablistPins = []struct{ fn, what, re string }{
	{"showTab", "aria-selected follows the selected tab", `\.setAttribute\(\s*'aria-selected'\s*,\s*t\s*===\s*tab\s*\?\s*'true'\s*:\s*'false'\s*\)`},
	{"showTab", "roving tabindex: only the selected tab is in the Tab order", `\.tabIndex\s*=\s*\(?\s*t\s*===\s*tab\s*\)?\s*\?\s*0\s*:\s*-1\b`},
	{"wireTablistKeys", "one keydown handler on #portal-tablist", `getElementById\(\s*'portal-tablist'\s*\)[\s\S]*\.addEventListener\(\s*'keydown'`},
	{"wireTablistKeys", "modified keys (browser shortcuts) are left alone", `if\s*\(\s*e\.altKey\s*\|\|\s*e\.ctrlKey\s*\|\|\s*e\.metaKey\s*\)\s*return\b`},
	{"wireTablistKeys", "hidden tabs are skipped", `\.filter\(\s*\(?\s*t\s*\)?\s*=>\s*!\s*t\.hidden\s*\)`},
	{"wireTablistKeys", "ArrowRight: next tab, wrapping", `case\s*'ArrowRight'\s*:\s*next\s*=\s*tabs\[\s*\(\s*i\s*\+\s*1\s*\)\s*%\s*tabs\.length\s*\]`},
	{"wireTablistKeys", "ArrowLeft: previous tab, wrapping", `case\s*'ArrowLeft'\s*:\s*next\s*=\s*tabs\[\s*\(\s*i\s*-\s*1\s*\+\s*tabs\.length\s*\)\s*%\s*tabs\.length\s*\]`},
	{"wireTablistKeys", "Home: first tab", `case\s*'Home'\s*:\s*next\s*=\s*tabs\[\s*0\s*\]`},
	{"wireTablistKeys", "End: last tab", `case\s*'End'\s*:\s*next\s*=\s*tabs\[\s*tabs\.length\s*-\s*1\s*\]`},
	{"wireTablistKeys", "Space activates the focused tab", `case\s*' '\s*:\s*next\s*=\s*cur\b`},
	{"wireTablistKeys", "any other key (Tab included) is not swallowed", `default\s*:\s*return\s*;`},
	{"wireTablistKeys", "a handled key moves focus and the hash (showTab renders it)", `e\.preventDefault\(\)\s*;\s*next\.focus\(\)\s*;\s*location\.hash\s*=\s*'#'\s*\+\s*next\.dataset\.tab\b`},
}

// checkTablistScript checks tablistPins against the router source. Whole-line
// `//` and <!-- --> comments are removed first, so commenting a line out
// removes it.
func checkTablistScript(router string) error {
	code := stripEscComments(router)
	var errs []error
	for _, p := range tablistPins {
		body := jsFuncBody(code, p.fn)
		if body == "" {
			errs = append(errs, fmt.Errorf("core-router.tmpl has no function %s", p.fn))
			continue
		}
		if !regexp.MustCompile(p.re).MatchString(body) {
			errs = append(errs, fmt.Errorf("core-router.tmpl %s() no longer has: %s", p.fn, p.what))
		}
	}
	return errors.Join(errs...)
}

// TestPortal_TablistKeyboardModelPinned runs checkTablistScript against the
// embedded router partial.
func TestPortal_TablistKeyboardModelPinned(t *testing.T) {
	if err := checkTablistScript(partialBody(portalPartials(t), "core-router.tmpl")); err != nil {
		t.Error(err)
	}
}

// TestPortal_TablistPinsRejectMutations: each case is one edit to the real
// router that breaks the keyboard model, and the check must name it.
func TestPortal_TablistPinsRejectMutations(t *testing.T) {
	router := partialBody(portalPartials(t), "core-router.tmpl")
	if err := checkTablistScript(router); err != nil {
		t.Fatalf("unmutated router fails checkTablistScript: %v", err)
	}
	const ariaSel = "link.setAttribute('aria-selected', t === tab ? 'true' : 'false');"
	cases := []struct {
		name, wantErr string
		edit          func(string) string
	}{
		{"aria-selected update removed", "aria-selected follows", replaceOnce(ariaSel, "")},
		{"aria-selected update commented out", "aria-selected follows", replaceOnce(ariaSel, "// "+ariaSel)},
		{"aria-selected always true", "aria-selected follows", replaceOnce("t === tab ? 'true' : 'false'", "'true'")},
		{"aria-selected update moved out of showTab", "showTab() no longer has: aria-selected", func(s string) string {
			s = strings.Replace(s, ariaSel, "", 1)
			return strings.Replace(s, "function applyRole() {", "function syncSelected(link, t, tab) {\n    "+ariaSel+"\n  }\n\n  function applyRole() {", 1)
		}},
		{"roving tabindex removed", "roving tabindex", replaceOnce("link.tabIndex = (t === tab) ? 0 : -1;", "")},
		{"every tab left in the Tab order", "roving tabindex", replaceOnce("(t === tab) ? 0 : -1", "0")},
		{"ArrowLeft branch removed", "ArrowLeft", replaceOnce("case 'ArrowLeft': next = tabs[(i - 1 + tabs.length) % tabs.length]; break;", "")},
		{"ArrowRight no longer wraps", "ArrowRight", replaceOnce("tabs[(i + 1) % tabs.length]", "tabs[i + 1]")},
		{"Home branch removed", "Home: first tab", replaceOnce("case 'Home': next = tabs[0]; break;", "")},
		{"End off by one", "End: last tab", replaceOnce("tabs[tabs.length - 1]", "tabs[tabs.length]")},
		{"Space branch removed", "Space activates", replaceOnce("case ' ': next = cur; break;", "")},
		{"hidden tabs no longer skipped", "hidden tabs are skipped", replaceOnce(".filter((t) => !t.hidden)", "")},
		{"every other key swallowed", "not swallowed", replaceOnce("default: return;", "")},
		{"focus no longer follows the key", "moves focus", replaceOnce("next.focus();", "")},
		{"modifier guard removed", "modified keys", replaceOnce("if (e.altKey || e.ctrlKey || e.metaKey) return;", "")},
		{"showTab renamed away", "has no function showTab", replaceOnce("function showTab(tab)", "function renderTab(tab)")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.edit(router)
			if mutated == router {
				t.Fatalf("mutation changed nothing — the text it rewrites is no longer in core-router.tmpl")
			}
			err := checkTablistScript(mutated)
			if err == nil {
				t.Fatalf("check passed a mutated router; want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("check failed, but not for the mutation under test.\n got: %v\nwant substring: %q", err, tc.wantErr)
			}
		})
	}
}
