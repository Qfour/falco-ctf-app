package view

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// P28-0a (4), app#285: the tablist / live-region wiring. Source-text checks on
// the rendered document and the router partial; keyboard behavior itself is a
// manual check (see portal_a11y_test.go).

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
