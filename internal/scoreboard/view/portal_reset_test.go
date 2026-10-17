package view

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The admin "Reset scoreboard" handler (pane-scoreboard.tmpl, and the dashboard
// templates/index.html) answers a failure with the server's own sentence, the way the
// admin rename does (portal_nameproblem_test.go; app#411, app#415): serverErrorText ->
// alert() as TEXT, with no reason written out by hand ("Admin only." went stale the day
// the rule behind a 403 changed). The handler is cut out of both sources and checked
// statically and by running its alert argument.

// resetHandler cuts the reset handler out of src: from `const resetBtn` to the closing
// brace of its `if (resetBtn) {` block (2-space indent in both sources).
func resetHandler(t *testing.T, name, src string) string {
	t.Helper()
	start := strings.Index(src, "const resetBtn = document.getElementById(")
	if start < 0 {
		t.Fatalf("%s: the reset handler (const resetBtn) was not found", name)
	}
	end := strings.Index(src[start:], "\n  }\n")
	if end < 0 {
		t.Fatalf("%s: the end of the reset handler was not found", name)
	}
	return src[start : start+end+len("\n  }")]
}

var resetAlertRe = regexp.MustCompile(`(?m)^\s*alert\((\x27Reset failed \(HTTP .*)\);$`)

func TestAdminReset_ShowsTheServersSentenceAsText(t *testing.T) {
	for _, name := range renameSources {
		h := resetHandler(t, name, renameSource(t, name))
		if !strings.Contains(h, "await serverErrorText(r)") {
			t.Errorf("%s: the reset failure branch lacks await serverErrorText(r)", name)
		}
		for _, bad := range []string{"Admin only", "innerHTML", "insertAdjacentHTML", "outerHTML", "document.write"} {
			if strings.Contains(h, bad) {
				t.Errorf("%s: the reset handler contains %q (the reason is the server's, shown as text)", name, bad)
			}
		}
		if len(resetAlertRe.FindAllStringSubmatch(h, -1)) != 1 {
			t.Errorf("%s: want exactly one alert('Reset failed (HTTP ' ...) line in the reset handler", name)
		}
	}
}

// TestAdminReset_AlertSentence RUNS the alert argument of both handlers for the three
// answers: a 403 with the server's sentence, a 500 with a body, and a 403 with no body
// (status and a full stop; no invented reason).
func TestAdminReset_AlertSentence(t *testing.T) {
	cases := []struct {
		status int
		why    string
		want   string
	}{
		{403, "admin only", "Reset failed (HTTP 403): admin only"},
		{500, "internal error", "Reset failed (HTTP 500): internal error"},
		{403, "", "Reset failed (HTTP 403)."},
		{500, "<img src=x onerror=alert(1)>", "Reset failed (HTTP 500): <img src=x onerror=alert(1)>"},
	}
	for _, name := range renameSources {
		m := resetAlertRe.FindStringSubmatch(resetHandler(t, name, renameSource(t, name)))
		if m == nil {
			t.Fatalf("%s: the alert line was not found", name)
		}
		for _, c := range cases {
			var got string
			driver := "var out = " + m[1] + ";"
			runJS(t, "var r = {status: "+fmt.Sprint(c.status)+"}; var why = "+jsString(c.why)+";", driver, nil, &got)
			if got != c.want {
				t.Errorf("%s: status %d, why %q: alert shows %q, want %q", name, c.status, c.why, got, c.want)
			}
		}
	}
}
