package view

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// profileLabel is the ONE string participant-facing prose uses to point at the
// place where the display name and avatar are set. It is "<tab label> ›
// <section heading>": the portal's tab for the Me pane is labelled
// "Scoreboard" (its internal id is "me"; renaming the tab is a CEO decision),
// and the form sits under the "Profile" heading in pane-me.tmpl.
//
// The prose that quotes it is outside the Go packages (challenges/, docs-site/),
// so nothing else notices when the tab or the heading is renamed. This test
// ties both ends: the label must appear verbatim in each prose file, and its
// two halves must exist in the rendered portal (R2#1, ADR-0034 S1).
const profileLabel = "Scoreboard タブ › Profile"

// profileLabelFiles are the participant-facing files that name the label.
// Paths are relative to this package directory.
var profileLabelFiles = []string{
	"../../../challenges/banner.sh",
	"../../../challenges/00-tutorial/fixtures/welcome.txt",
	"../../../challenges/00-tutorial/journey.yaml",
	"../../../challenges/PARTICIPANT-HANDBOOK.md",
	"../../../challenges/PRESENTATION.md",
	"../../../docs-site/docs/index.md",
	"../../../docs-site/docs/cheatsheet.md",
}

func TestProfileLabel_ProseMatchesPortal(t *testing.T) {
	tabName, heading, ok := strings.Cut(profileLabel, " タブ › ")
	if !ok {
		t.Fatalf("profileLabel %q is not \"<tab> タブ › <heading>\"", profileLabel)
	}

	// The portal side: the tab link text and the Profile heading.
	r := httptest.NewRequest("GET", "/portal", nil)
	w := httptest.NewRecorder()
	if err := renderPortal(w, r, nil, nil, ""); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}
	if want := `data-tab="me" href="#me">` + tabName + `</a>`; !strings.Contains(w.Body.String(), want) {
		t.Errorf("the Me tab link is not labelled %q (want %s in the rendered portal)", tabName, want)
	}
	pane := partialBody(portalPartials(t), "pane-me.tmpl")
	if want := `id="pane-me-profile-h">` + heading + `</h2>`; !strings.Contains(pane, want) {
		t.Errorf("pane-me.tmpl has no %q heading (want %s)", heading, want)
	}

	// The prose side: every file names the label verbatim.
	for _, p := range profileLabelFiles {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("read %s: %v", p, err)
			continue
		}
		if !strings.Contains(string(b), profileLabel) {
			t.Errorf("%s does not contain %q", p, profileLabel)
		}
		if strings.Contains(string(b), "Me 画面") {
			t.Errorf("%s still points at the \"Me 画面\", which has no tab or heading of that name", p)
		}
	}
}
