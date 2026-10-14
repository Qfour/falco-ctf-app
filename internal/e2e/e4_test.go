//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// E4 (I8, the frame-src side; ADR-0031 V1 / D2): the portal builds the
// caller's own terminal iframe — https://<user>.<PORTAL_TTYD_SUFFIX>, from the
// identity the server derived, never from the page — and the page's own CSP
// lets that iframe load.
//
// The cookie side of I8 (oauth2-proxy's cookie reaching the cross-origin
// iframe) is out of scope (ADR-0031 D2 (i)): the ttyd stub here has no login.
//
// It turns red when frame-src is broken (internal/scoreboard/view/csp.go: the
// iframe is blocked, the stub sees nothing and a CSP violation is reported)
// and when the suffix is lost (the placeholder is rendered and no iframe
// exists). The output of both deliberate breaks is in the H1 PR body.
func TestE2E_E4_TerminalIframeIsTheCallersOwnTtydAndTheCSPLetsItLoad(t *testing.T) {
	e := NewEnv(t, harness.SeedFresh)
	b := e.B
	want := "https://" + e.User + "." + harness.TtydSuffix
	if e.Stub.Origin() != want {
		t.Fatalf("the ttyd stub serves %s, but the portal must point user %s at %s", e.Stub.Origin(), e.User, want)
	}

	b.Open("/portal#terminal")
	b.Wait("the terminal tab", `document.getElementById('pane-terminal').classList.contains('active')`)
	// Either branch of pane-terminal's render() is the positive sync point —
	// the iframe, or the "not configured" placeholder an empty suffix gives —
	// so a lost suffix fails here with what was rendered, not at a deadline.
	b.Wait("the terminal pane's render (an iframe or the placeholder)",
		`!!document.querySelector('#pane-terminal-page iframe, #pane-terminal-page .term-placeholder')`)
	frames := Eval[[]string](b, `Array.from(document.querySelectorAll('iframe')).map(function (f) { return f.id + ' ' + (f.getAttribute('src') || ''); })`)
	if len(frames) != 1 || frames[0] != "pane-terminal-iframe "+want {
		placeholder := Eval[string](b, `(document.querySelector('#pane-terminal-page .term-placeholder') || {}).textContent || ''`)
		t.Fatalf("iframes on the portal = %q, want exactly #pane-terminal-iframe with src %s (I8: the caller's own ttyd)\nplaceholder: %q\n%s",
			frames, want, strings.TrimSpace(placeholder), b.diagnostics())
	}

	// The iframe's request reached the stub: the browser resolved the name to
	// it, trusted only its key, and the CSP let the frame load. The deadline
	// is how long a blocked frame takes to fail, not something waited for.
	ctx, cancel := context.WithTimeout(e.Ctx, defaultWaitLimit)
	defer cancel()
	if err := e.Stub.Wait(ctx, "the iframe's GET at the ttyd stub", func(hits []string) bool {
		for _, h := range hits {
			if h == "GET "+e.Stub.Host()+"/" {
				return true
			}
		}
		return false
	}); err != nil {
		t.Fatalf("%v\n%s", err, b.diagnostics())
	}
	for _, h := range e.Stub.Hits() {
		if !strings.HasPrefix(h, "GET "+e.Stub.Host()+"/") {
			t.Errorf("the ttyd stub saw %q: only the user's own host, read-only", h)
		}
	}

	// CSP violations 0, no other origin, no write (opening the portal is not
	// an action that writes).
	b.AssertClean(0, nil)
}
