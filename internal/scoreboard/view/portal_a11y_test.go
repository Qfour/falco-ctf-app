package view

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// P28-0a (3), REFACTORING.md P28 acceptance 7: the accessibility floor of the
// portal, pinned so a later palette or CSS change cannot silently drop it.
// Everything here reads source text (tokens.css, the partials, the rendered
// document); the browser-level behavior (a ring actually painted, motion
// actually stopped) is NOT proved by these tests and is listed in the PR as a
// manual check until the ADR-0031 harness exists.

// tokenValue resolves a custom property in tokens.css to a #RRGGBB literal,
// following var(--other) aliases. The file keeps one hex literal per color
// (app#116), so the chain always ends at one.
func tokenValue(t *testing.T, css, name string) string {
	t.Helper()
	// Not an anchored-at-line-start match: tokens.css puts only one
	// declaration per line, and a value may be followed by a /* comment */.
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `:\s*([^;]+);`)
	for depth := 0; depth < 8; depth++ {
		m := re.FindStringSubmatch(css)
		if m == nil {
			t.Fatalf("tokens.css has no %s", name)
		}
		v := strings.TrimSpace(m[1])
		if strings.HasPrefix(v, "#") {
			if len(v) != 7 {
				t.Fatalf("%s = %q, want #RRGGBB", name, v)
			}
			return v
		}
		a := regexp.MustCompile(`^var\((--[a-z0-9-]+)\)$`).FindStringSubmatch(v)
		if a == nil {
			t.Fatalf("%s = %q, want a #RRGGBB literal or var(--alias)", name, v)
		}
		name = a[1]
		re = regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `:\s*([^;]+);`)
	}
	t.Fatalf("alias chain for %s does not end", name)
	return ""
}

func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	ch := func(s string) float64 {
		n, err := strconv.ParseUint(s, 16, 8)
		if err != nil {
			t.Fatalf("bad hex %q: %v", hex, err)
		}
		c := float64(n) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(hex[1:3]) + 0.7152*ch(hex[3:5]) + 0.0722*ch(hex[5:7])
}

func contrastRatio(t *testing.T, a, b string) float64 {
	la, lb := relLuminance(t, a), relLuminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestTokens_TextContrastMeetsWCAGAA: every text token is >= 4.5:1 (WCAG 2.x
// AA, normal-size text) on every surface the portal paints it on, and the
// keyboard focus ring is >= 3:1 (non-text contrast). --text-mute was 3.28:1 on
// --surface-2 before P28-0a.
func TestTokens_TextContrastMeetsWCAGAA(t *testing.T) {
	raw, err := os.ReadFile("static/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(raw)
	surfaces := []string{"--bg", "--bg-elev", "--surface", "--surface-2"}
	texts := []string{"--text", "--text-dim", "--text-mute", "--falco", "--warn", "--evade", "--danger", "--gold", "--silver", "--bronze"}
	for _, s := range surfaces {
		bg := tokenValue(t, css, s)
		for _, f := range texts {
			if r := contrastRatio(t, tokenValue(t, css, f), bg); r < 4.5 {
				t.Errorf("%s on %s = %.2f:1, want >= 4.5:1 (WCAG AA)", f, s, r)
			}
		}
		if r := contrastRatio(t, tokenValue(t, css, "--focus-ring"), bg); r < 3 {
			t.Errorf("--focus-ring on %s = %.2f:1, want >= 3:1", s, r)
		}
	}
	// The ring token the portal's CSS actually reads must alias the base one.
	if got, want := tokenValue(t, css, "--p-focus-ring"), tokenValue(t, css, "--focus-ring"); got != want {
		t.Errorf("--p-focus-ring = %s, want %s", got, want)
	}
}

// TestPortalCSS_ReducedMotionAndFocusRing: the stylesheet carries the
// reduced-motion block and the :focus-visible ring, and nothing removes an
// outline without putting one back.
func TestPortalCSS_ReducedMotionAndFocusRing(t *testing.T) {
	css := partialBody(portalPartials(t), "css.tmpl")
	if css == "" {
		t.Fatal("css.tmpl not found among the portal partials")
	}
	m := regexp.MustCompile(`(?s)@media \(prefers-reduced-motion: reduce\)\s*\{(.*?)\n  \}`).FindStringSubmatch(css)
	if m == nil {
		t.Error("css.tmpl has no @media (prefers-reduced-motion: reduce) block")
		m = []string{"", ""}
	}
	for _, want := range []string{"animation-duration: 0.01ms !important", "animation-iteration-count: 1 !important", "transition-duration: 0.01ms !important", "scroll-behavior: auto !important"} {
		if m[1] != "" && !strings.Contains(m[1], want) {
			t.Errorf("the reduced-motion block lacks %q", want)
		}
	}
	if !strings.Contains(css, ":focus-visible { outline: 2px solid var(--p-focus-ring)") {
		t.Error("css.tmpl has no :focus-visible ring painted with var(--p-focus-ring)")
	}
	// The only `outline: none` allowed: the mouse-focus reset (the ring is
	// still on :focus-visible) and a radio whose enclosing .dest-option
	// paints the ring instead. A new `:focus { outline: none }` on a control
	// would leave keyboard users without any indicator.
	allowed := func(sel string) bool {
		return sel == ":focus:not(:focus-visible)" || sel == "#pane-board .dest-option input:focus-visible"
	}
	for _, mm := range regexp.MustCompile(`([^{}]+)\{[^{}]*outline:\s*none`).FindAllStringSubmatch(css, -1) {
		sel := strings.TrimSpace(mm[1])
		if i := strings.LastIndex(sel, "*/"); i >= 0 {
			sel = strings.TrimSpace(sel[i+2:])
		}
		if !allowed(sel) {
			t.Errorf("css.tmpl removes the outline on %q without a replacement indicator", sel)
		}
	}
}
