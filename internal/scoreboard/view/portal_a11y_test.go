package view

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// P28-0a (3), REFACTORING.md P28 acceptance 7: the accessibility floor of the
// portal, pinned so a later palette or CSS change cannot silently drop it.
// Everything here reads source text (tokens.css, the partials); the
// browser-level behavior (a ring actually painted, motion actually stopped)
// is NOT proved by these tests and is listed in the PR as a manual check
// until the ADR-0031 harness exists.

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
// keyboard focus ring is >= 3:1 (non-text contrast) — both the ring token and
// the --p-accent it falls back to (focusRingRef). --text-mute was 3.28:1 on
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
		// --p-accent is the ring a browser with a stale tokens.css paints
		// (focusRingRef), so it must be a valid ring as well. tokenValue
		// fails the test if tokens.css no longer defines it, which would make
		// the fallback dead.
		for _, ring := range []string{"--focus-ring", "--p-accent"} {
			if r := contrastRatio(t, tokenValue(t, css, ring), bg); r < 3 {
				t.Errorf("%s on %s = %.2f:1, want >= 3:1 (it paints the focus ring)", ring, s, r)
			}
		}
	}
	// The ring token the portal's CSS reads must alias the base one.
	if got, want := tokenValue(t, css, "--p-focus-ring"), tokenValue(t, css, "--focus-ring"); got != want {
		t.Errorf("--p-focus-ring = %s, want %s", got, want)
	}
}

// focusRingRef is the ONE spelling portal CSS may use to read the ring token.
// tokens.css is served from a fixed URL with a 24h immutable cache
// (vendorassets.go) while the portal HTML that carries this CSS is not cached,
// so for up to a day after a deploy a browser can pair the new HTML with the
// tokens.css from before --p-focus-ring existed. A bare var(--p-focus-ring) is
// then invalid at computed-value time, the outline falls back to
// outline-style: none, and keyboard users get NO ring, which is worse than the
// UA default it replaced (review-5x T2, R3#1 / R4#1). --p-accent has been in
// tokens.css since app#116, so the fallback always resolves. Change this
// constant (to drop the fallback) only after ADR-0028's content-hash URLs
// have landed.
const focusRingRef = "var(--p-focus-ring, var(--p-accent))"

// focusRingOutline is the outline every ring painted by the a11y CSS uses.
const focusRingOutline = "2px solid " + focusRingRef

// outlineRemovalAllowed lists the only selectors on which portal CSS may
// remove the outline, each mapped to the selector whose rule paints the ring
// in its place (outline: focusRingOutline). A removal passes only while that
// replacement exists, so deleting the replacement fails as well.
//   - :focus:not(:focus-visible): the mouse-focus reset; the global
//     :focus-visible ring still covers keyboard focus.
//   - the radio inside a boxed .dest-option: the box is ringed instead.
//
// Anything else (a pane's `input:focus { outline: none }`, an inline style, a
// script write) leaves keyboard users without an indicator.
var outlineRemovalAllowed = map[string]string{
	":focus:not(:focus-visible)":                   ":focus-visible",
	"#pane-board .dest-option input:focus-visible": "#pane-board .dest-option:has(input:focus-visible)",
}

// reducedMotionDecls is what the one reduced-motion block must set on
// `*, *::before, *::after`: every animation and transition ends at once on its
// final state (0.01ms, not 0s, so animationend / transitionend still fire).
var reducedMotionDecls = [][2]string{
	{"animation-duration", "0.01ms !important"},
	{"animation-delay", "0s !important"},
	{"animation-iteration-count", "1 !important"},
	{"transition-duration", "0.01ms !important"},
	{"transition-delay", "0s !important"},
	{"scroll-behavior", "auto !important"},
}

// cssDecl is one `prop: value` declaration. prop is lower-cased; value has its
// whitespace collapsed and keeps any !important.
type cssDecl struct{ prop, value string }

// cssRule is one style rule found in the portal source, or the declaration
// list of an inline style attribute / a script write (selectors == nil).
type cssRule struct {
	where     string   // partial:line
	partial   string   // basename of the partial
	at        []string // enclosing at-rule preludes, outermost first, lower-cased
	selectors []string // the selector list split at top-level commas
	decls     []cssDecl
}

// cssAtBlock is one at-rule block (@media, @keyframes, ...).
type cssAtBlock struct {
	where   string
	partial string
	at      []string // enclosing at-rule preludes
	prelude string   // lower-cased, whitespace collapsed
	rules   []*cssRule
}

// cssSource is one piece of CSS text as scanned (comments blanked), kept for
// the ring-token scan.
type cssSource struct {
	partial string
	line    int
	text    string
}

// portalCSS is all the CSS the portal partials carry: every <style> element,
// every inline style attribute (markup or a JS template literal), and every
// script write of a style (style = / setAttribute('style') / cssText /
// .style.outline* / setProperty('outline*')).
type portalCSS struct {
	styleBlocks int
	rules       []*cssRule
	ats         []*cssAtBlock
	sources     []cssSource
}

var (
	a11yHTMLCommentRe   = regexp.MustCompile(`(?s)<!--.*?-->`)
	a11yJSLineCommentRe = regexp.MustCompile(`(?m)^[ \t]*//.*$`)
	a11yCSSCommentRe    = regexp.MustCompile(`(?s)/\*.*?\*/`)
	styleElemRe         = regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style\s*>`)
	// A JS ${...} interpolation or a {{...}} template action: a value the
	// scan cannot evaluate, replaced by a placeholder so its braces do not
	// read as CSS blocks.
	cssInterpRe = regexp.MustCompile(`\$\{[^{}]*\}|\{\{.*?\}\}`)

	quotedArg = `\s*(?:"([^"]*)"|'([^']*)'|` + "`([^`]*)`)"
	// Each sets a whole inline declaration list.
	inlineStyleRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bstyle\s*=` + quotedArg),                    // style="…" in markup or a template literal; el.style = '…'
		regexp.MustCompile(`setAttribute\(\s*['"]style['"]\s*,` + quotedArg), // el.setAttribute('style', '…')
		regexp.MustCompile(`\.cssText\s*\+?=` + quotedArg),                   // el.style.cssText = '…'
	}
	jsOutlinePropRe = regexp.MustCompile(`\.style\.(outline(?:Style|Width)?)\s*=` + quotedArg)
	jsSetPropertyRe = regexp.MustCompile(`\.style\.setProperty\(\s*['"](outline(?:-style|-width)?)['"]\s*,` + quotedArg)

	cssZeroLengthRe = regexp.MustCompile(`^[+-]?(?:0+(?:\.0*)?|\.0+)[a-z]*$`)
	cssImportantRe  = regexp.MustCompile(`\s*!\s*important\s*$`)
	cssPunctWSRe    = regexp.MustCompile(`\s*([(),])\s*`)
	reducedMotionRe = regexp.MustCompile(`prefers-reduced-motion\s*:\s*reduce`)
	ringTokenRefRe  = regexp.MustCompile(`var\(\s*--(?:p-)?focus-ring\b`)
	camelUpperRe    = regexp.MustCompile(`([A-Z])`)
)

// blankKeepLines replaces every match of re with repl plus the newlines the
// match contained, so line numbers after it stay right.
func blankKeepLines(re *regexp.Regexp, s, repl string) string {
	return re.ReplaceAllStringFunc(s, func(m string) string { return repl + strings.Repeat("\n", strings.Count(m, "\n")) })
}

func lineAt(s string, off int) int { return 1 + strings.Count(s[:off], "\n") }

// firstGroup returns the first submatch at or after group index g that took
// part in the match m.
func firstGroup(s string, m []int, g int) string {
	for ; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 {
			return s[m[2*g]:m[2*g+1]]
		}
	}
	return ""
}

// splitSelectors splits a selector list at commas outside (), [].
func splitSelectors(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.Join(strings.Fields(s[start:i]), " "))
				start = i + 1
			}
		}
	}
	return append(out, strings.Join(strings.Fields(s[start:]), " "))
}

// normCSS makes two spellings of one value comparable: lower case, collapsed
// whitespace, none around ( ) and commas.
func normCSS(v string) string {
	return strings.TrimSpace(cssPunctWSRe.ReplaceAllString(strings.ToLower(strings.Join(strings.Fields(v), " ")), "$1"))
}

// parse adds the CSS in src (from partial, starting at line) to pc. inline
// marks a bare declaration list (a style attribute or a script write), which
// becomes one selector-less rule. A stylesheet the scan cannot parse is an
// error, never skipped: a gate that drops what it cannot read passes it.
func (pc *portalCSS) parse(partial string, line int, src string, inline bool) error {
	const inlineSel = "__inline__"
	src = cssInterpRe.ReplaceAllString(src, "_")
	if inline {
		src = inlineSel + "{" + src + "}"
	}
	src = blankKeepLines(a11yCSSCommentRe, src, " ")
	pc.sources = append(pc.sources, cssSource{partial: partial, line: line, text: src})

	type frame struct {
		at   *cssAtBlock
		rule *cssRule
	}
	var stack []frame
	var buf strings.Builder
	where := func() string { return fmt.Sprintf("%s:%d", partial, line) }
	enclosing := func() []string {
		var a []string
		for _, f := range stack {
			if f.at != nil {
				a = append(a, f.at.prelude)
			}
		}
		return a
	}
	flush := func() {
		seg := strings.TrimSpace(buf.String())
		buf.Reset()
		i := strings.IndexByte(seg, ':')
		if len(stack) == 0 || i <= 0 {
			return
		}
		d := cssDecl{prop: strings.ToLower(strings.TrimSpace(seg[:i])), value: strings.Join(strings.Fields(seg[i+1:]), " ")}
		if top := stack[len(stack)-1]; top.rule != nil {
			top.rule.decls = append(top.rule.decls, d)
		} else { // a declaration directly in an at-rule (@font-face)
			r := &cssRule{where: where(), partial: partial, at: enclosing(), decls: []cssDecl{d}}
			pc.rules = append(pc.rules, r)
			top.at.rules = append(top.at.rules, r)
		}
	}
	for i := 0; i < len(src); i++ {
		switch c := src[i]; c {
		case '\n':
			line++
			buf.WriteByte(c)
		case '"', '\'':
			j := i + 1
			for ; j < len(src) && src[j] != c; j++ {
				if src[j] == '\\' {
					j++
				}
			}
			if j >= len(src) {
				return fmt.Errorf("%s: unterminated string in CSS", where())
			}
			line += strings.Count(src[i:j], "\n")
			buf.WriteString(src[i : j+1])
			i = j
		case '{':
			prelude := strings.Join(strings.Fields(buf.String()), " ")
			buf.Reset()
			if strings.HasPrefix(prelude, "@") {
				a := &cssAtBlock{where: where(), partial: partial, at: enclosing(), prelude: strings.ToLower(prelude)}
				pc.ats = append(pc.ats, a)
				stack = append(stack, frame{at: a})
				continue
			}
			r := &cssRule{where: where(), partial: partial, at: enclosing()}
			if prelude != inlineSel {
				r.selectors = splitSelectors(prelude)
			}
			pc.rules = append(pc.rules, r)
			if n := len(stack); n > 0 && stack[n-1].at != nil {
				stack[n-1].at.rules = append(stack[n-1].at.rules, r)
			}
			stack = append(stack, frame{rule: r})
		case ';':
			flush()
		case '}':
			if len(stack) == 0 {
				return fmt.Errorf("%s: unbalanced '}' in CSS", where())
			}
			flush()
			stack = stack[:len(stack)-1]
		default:
			buf.WriteByte(c)
		}
	}
	if len(stack) > 0 {
		return fmt.Errorf("%s: %d unclosed '{' in CSS", where(), len(stack))
	}
	if rest := strings.TrimSpace(buf.String()); rest != "" {
		return fmt.Errorf("%s: text outside any rule in CSS: %q", where(), rest)
	}
	return nil
}

// collectPortalCSS reads every portal partial (readPortalPartials, so a
// partial added later is covered without naming it) and gathers all the CSS
// they carry (see portalCSS). HTML comments and whole-line `//` comments are
// blanked first. It errors when a stylesheet does not parse and when no
// <style> element is found at all.
func collectPortalCSS(fsys fs.FS) (*portalCSS, error) {
	parts, err := readPortalPartials(fsys)
	if err != nil {
		return nil, err
	}
	pc := &portalCSS{}
	var errs []error
	for _, p := range parts {
		src := blankKeepLines(a11yJSLineCommentRe, blankKeepLines(a11yHTMLCommentRe, p.body, " "), "")
		// <style> elements first; then blank them out so the attribute scan
		// below does not read CSS (or a comment inside it) as markup.
		var rest strings.Builder
		prev := 0
		for _, l := range styleElemRe.FindAllStringSubmatchIndex(src, -1) {
			pc.styleBlocks++
			if err := pc.parse(p.name, lineAt(src, l[2]), src[l[2]:l[3]], false); err != nil {
				errs = append(errs, err)
			}
			rest.WriteString(src[prev:l[0]])
			rest.WriteString(strings.Repeat("\n", strings.Count(src[l[0]:l[1]], "\n")))
			prev = l[1]
		}
		rest.WriteString(src[prev:])
		r := rest.String()
		for _, re := range inlineStyleRes {
			for _, m := range re.FindAllStringSubmatchIndex(r, -1) {
				if err := pc.parse(p.name, lineAt(r, m[0]), firstGroup(r, m, 1), true); err != nil {
					errs = append(errs, err)
				}
			}
		}
		for _, m := range jsOutlinePropRe.FindAllStringSubmatchIndex(r, -1) {
			prop := strings.ToLower(camelUpperRe.ReplaceAllString(r[m[2]:m[3]], "-$1")) // outlineStyle -> outline-style
			if err := pc.parse(p.name, lineAt(r, m[0]), prop+":"+firstGroup(r, m, 2), true); err != nil {
				errs = append(errs, err)
			}
		}
		for _, m := range jsSetPropertyRe.FindAllStringSubmatchIndex(r, -1) {
			if err := pc.parse(p.name, lineAt(r, m[0]), r[m[2]:m[3]]+":"+firstGroup(r, m, 2), true); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if pc.styleBlocks == 0 || len(pc.rules) == 0 {
		errs = append(errs, fmt.Errorf("found %d <style> element(s) and %d rule(s) across the portal partials — the a11y CSS gate would be scanning nothing", pc.styleBlocks, len(pc.rules)))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return pc, nil
}

// removesOutline reports whether d takes the outline away: outline with a
// none / zero-width / initial / unset component, outline-style none (or
// initial / unset), outline-width 0.
func removesOutline(d cssDecl) bool {
	v := strings.ToLower(cssImportantRe.ReplaceAllString(d.value, ""))
	switch d.prop {
	case "outline":
		for _, tok := range strings.Fields(v) {
			if tok == "none" || tok == "initial" || tok == "unset" || cssZeroLengthRe.MatchString(tok) {
				return true
			}
		}
	case "outline-style":
		return v == "none" || v == "initial" || v == "unset"
	case "outline-width":
		return cssZeroLengthRe.MatchString(v)
	}
	return false
}

func declValue(r *cssRule, prop string) (string, bool) {
	for _, d := range r.decls {
		if d.prop == prop {
			return d.value, true
		}
	}
	return "", false
}

func hasSelector(r *cssRule, sel string) bool {
	for _, s := range r.selectors {
		if s == sel {
			return true
		}
	}
	return false
}

// paintsRing reports whether some rule on sel sets outline: focusRingOutline.
func (pc *portalCSS) paintsRing(sel string) bool {
	for _, r := range pc.rules {
		if v, ok := declValue(r, "outline"); ok && hasSelector(r, sel) && normCSS(v) == normCSS(focusRingOutline) {
			return true
		}
	}
	return false
}

// checkPortalA11yCSS verifies, over ALL the CSS the portal partials carry
// (collectPortalCSS — not one named file, which a split into partials would
// silently shrink to nothing; review-5x T2 R4#3), that:
//
//  1. Nothing removes the outline except the outlineRemovalAllowed selectors,
//     and each of those still has its replacement ring. An inline style or a
//     script write that removes it always fails.
//  2. Every reference to the ring token is spelled focusRingRef (with the
//     --p-accent fallback).
//  3. There is exactly ONE global :focus-visible ring rule in the whole
//     document; it sets outline: focusRingOutline, is not inside an at-rule,
//     and lives in portalA11yCSSPartial (the CSS partial the root calls last,
//     checkPortalAssembly rule 6).
//  4. There is exactly ONE @media (prefers-reduced-motion: reduce) block; it is
//     not nested, lives in portalA11yCSSPartial, and sets reducedMotionDecls
//     on `*, *::before, *::after`.
func checkPortalA11yCSS(fsys fs.FS) error {
	pc, err := collectPortalCSS(fsys)
	if err != nil {
		return err
	}
	var errs []error

	// 1. outline removal
	for _, r := range pc.rules {
		for _, d := range r.decls {
			if !removesOutline(d) {
				continue
			}
			if r.selectors == nil {
				errs = append(errs, fmt.Errorf("%s: a style attribute / script write removes the outline (%s: %s) — only a rule on one of the allowlisted selectors may, and only while its replacement ring exists", r.where, d.prop, d.value))
				continue
			}
			for _, sel := range r.selectors {
				ring, ok := outlineRemovalAllowed[sel]
				switch {
				case !ok:
					errs = append(errs, fmt.Errorf("%s: removes the outline on %q (%s: %s) without a replacement indicator — keyboard users would see no focus at all", r.where, sel, d.prop, d.value))
				case !pc.paintsRing(ring):
					errs = append(errs, fmt.Errorf("%s: removes the outline on %q, but its replacement ring `%s { outline: %s }` is gone", r.where, sel, ring, focusRingOutline))
				}
			}
		}
	}

	// 2. ring token spelling
	for _, s := range pc.sources {
		for _, loc := range ringTokenRefRe.FindAllStringIndex(s.text, -1) {
			ref, depth := s.text[loc[0]:], 0
			for i := strings.IndexByte(ref, '('); i >= 0 && i < len(ref); i++ {
				if ref[i] == '(' {
					depth++
				} else if ref[i] == ')' {
					if depth--; depth == 0 {
						ref = ref[:i+1]
						break
					}
				}
			}
			if normCSS(ref) != normCSS(focusRingRef) {
				errs = append(errs, fmt.Errorf("%s:%d: reads the ring token as %q, want %q — a browser holding a tokens.css cached from before --p-focus-ring existed would paint no ring at all (see focusRingRef)", s.partial, s.line+strings.Count(s.text[:loc[0]], "\n"), strings.Join(strings.Fields(ref), " "), focusRingRef))
			}
		}
	}

	// 3. the one global :focus-visible ring
	var rings []*cssRule
	for _, r := range pc.rules {
		if !hasSelector(r, ":focus-visible") && !hasSelector(r, "*:focus-visible") {
			continue
		}
		for _, d := range r.decls {
			if d.prop == "outline" || d.prop == "outline-style" || d.prop == "outline-color" || d.prop == "outline-width" {
				rings = append(rings, r)
				break
			}
		}
	}
	if len(rings) != 1 {
		var at []string
		for _, r := range rings {
			at = append(at, r.where)
		}
		errs = append(errs, fmt.Errorf("found %d global :focus-visible ring rule(s) %v, want exactly 1 — the ring is defined once, in %s", len(rings), at, portalA11yCSSPartial))
	} else {
		r := rings[0]
		if v, _ := declValue(r, "outline"); normCSS(v) != normCSS(focusRingOutline) {
			errs = append(errs, fmt.Errorf("%s: the global :focus-visible ring sets outline: %q, want %q", r.where, v, focusRingOutline))
		}
		if len(r.at) > 0 {
			errs = append(errs, fmt.Errorf("%s: the global :focus-visible ring is inside an at-rule %q, so it applies only conditionally", r.where, r.at))
		}
		if r.partial != portalA11yCSSPartial {
			errs = append(errs, fmt.Errorf("%s: the global :focus-visible ring must be in %s (the CSS partial served last), not %s", r.where, portalA11yCSSPartial, r.partial))
		}
	}

	// 4. the one reduced-motion block
	var rm []*cssAtBlock
	for _, a := range pc.ats {
		if strings.HasPrefix(a.prelude, "@media") && reducedMotionRe.MatchString(a.prelude) {
			rm = append(rm, a)
		}
	}
	if len(rm) != 1 {
		var at []string
		for _, a := range rm {
			at = append(at, a.where)
		}
		errs = append(errs, fmt.Errorf("found %d @media (prefers-reduced-motion: reduce) block(s) %v, want exactly 1, in %s", len(rm), at, portalA11yCSSPartial))
	} else {
		a := rm[0]
		if len(a.at) > 0 {
			errs = append(errs, fmt.Errorf("%s: the reduced-motion block is nested in %q", a.where, a.at))
		}
		if a.partial != portalA11yCSSPartial {
			errs = append(errs, fmt.Errorf("%s: the reduced-motion block must be in %s (the CSS partial served last), not %s", a.where, portalA11yCSSPartial, a.partial))
		}
		var all *cssRule
		for _, r := range a.rules {
			if strings.Join(r.selectors, ", ") == "*, *::before, *::after" {
				all = r
			}
		}
		if all == nil {
			errs = append(errs, fmt.Errorf("%s: the reduced-motion block has no rule on `*, *::before, *::after`", a.where))
		} else {
			for _, want := range reducedMotionDecls {
				if v, ok := declValue(all, want[0]); !ok || normCSS(v) != normCSS(want[1]) {
					errs = append(errs, fmt.Errorf("%s: the reduced-motion block lacks %s: %s", a.where, want[0], want[1]))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// TestPortalCSS_ReducedMotionAndFocusRing runs checkPortalA11yCSS against the
// embedded partials.
func TestPortalCSS_ReducedMotionAndFocusRing(t *testing.T) {
	if err := checkPortalA11yCSS(portalFS); err != nil {
		t.Error(err)
	}
}

// portalFSReplaceRe returns a mutation that replaces every match of pattern in
// one partial, expanding $1 in repl (portalFSEdit fails the case if nothing
// matched).
func portalFSReplaceRe(name, pattern, repl string) func(*testing.T, fstest.MapFS) {
	re := regexp.MustCompile(pattern)
	return portalFSEdit(name, func(s string) string { return re.ReplaceAllString(s, repl) })
}

// TestPortalCSS_A11yGateRejectsMutations is the proof that
// checkPortalA11yCSS can fail, and that it reads beyond css.tmpl: each case
// applies ONE mutation to a copy of the real partials (helpers in
// portal_partials_test.go) and requires the check to report it. The unmutated
// copy must pass.
func TestPortalCSS_A11yGateRejectsMutations(t *testing.T) {
	if err := checkPortalA11yCSS(mutatedPortalFS(t, func(*testing.T, fstest.MapFS) {})); err != nil {
		t.Fatalf("unmutated copy fails checkPortalA11yCSS: %v", err)
	}
	const (
		a11y       = portalA11yCSSPartial
		globalRing = "  :focus-visible { outline: 2px solid " + focusRingRef + "; outline-offset: 2px; }\n"
		rmBlockRe  = `(?s)\n  @media \(prefers-reduced-motion: reduce\) \{.*?\n  \}\n`
	)
	inCSS := func(rule string) func(*testing.T, fstest.MapFS) {
		return portalFSEdit("css.tmpl", replaceOnce("</style>", "  "+rule+"\n</style>"))
	}
	cases := []struct {
		name    string
		mutate  func(*testing.T, fstest.MapFS)
		wantErr string
	}{
		// ---- 1. outline removal, wherever the CSS sits ----
		{"a pane's own <style> removes the outline", portalFSEdit("pane-me.tmpl", appendText("<style>\n  #pane-me input:focus { outline: none; }\n</style>\n")), `removes the outline on "#pane-me input:focus"`},
		{"outline: 0 in css.tmpl", inCSS("#pane-story .submit-form input:focus { outline: 0; }"), `removes the outline on "#pane-story .submit-form input:focus"`},
		{"outline: 0 none !important", inCSS("textarea:focus { outline: 0 none !important; }"), `removes the outline on "textarea:focus"`},
		{"outline-style: none", inCSS("button:focus { outline-style: none; }"), `removes the outline on "button:focus"`},
		{"outline-width: 0px", inCSS("a:focus-visible { outline-width: 0px; }"), `removes the outline on "a:focus-visible"`},
		{"removal nested in a media query", inCSS("@media (max-width: 720px) { #pane-board .ticket-open:focus { outline: none; } }"), `removes the outline on "#pane-board .ticket-open:focus"`},
		{"an allowed reset shares its selector list with a new one", portalFSEdit(a11y, replaceOnce(":focus:not(:focus-visible) { outline: none; }", ":focus:not(:focus-visible), select:focus { outline: none; }")), `removes the outline on "select:focus"`},
		{"inline style attribute in markup", portalFSEdit("pane-home.tmpl", appendText(`<div style="color: var(--p-text); outline: none">x</div>`+"\n")), "a style attribute / script write removes the outline"},
		{"inline style attribute in a JS template literal", portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  const tpl = `<input style=\"outline:0;width:${w}px\">`;\n")), "a style attribute / script write removes the outline"},
		{"script sets el.style.outline", portalFSEdit("pane-me.tmpl", replaceOnce("(function () {\n", "(function () {\n  document.body.style.outline = 'none';\n")), "a style attribute / script write removes the outline"},
		{"script sets el.style.outlineStyle", portalFSEdit("pane-board.tmpl", replaceOnce("(function () {\n", "(function () {\n  document.body.style.outlineStyle = \"none\";\n")), "a style attribute / script write removes the outline"},
		{"script uses style.setProperty", portalFSEdit("pane-board.tmpl", replaceOnce("(function () {\n", "(function () {\n  document.body.style.setProperty('outline-width', '0');\n")), "a style attribute / script write removes the outline"},
		{"script writes cssText", portalFSEdit("pane-story.tmpl", replaceOnce("(function () {\n", "(function () {\n  document.body.style.cssText = 'outline: none';\n")), "a style attribute / script write removes the outline"},
		{"script uses setAttribute('style')", portalFSEdit("pane-story.tmpl", replaceOnce("(function () {\n", "(function () {\n  document.body.setAttribute('style', 'outline:none');\n")), "a style attribute / script write removes the outline"},
		{"the radio's replacement ring is deleted", portalFSReplaceRe(a11y, `(?m)^.*\.dest-option:has\(input:focus-visible\).*\n`, ""), `removes the outline on "#pane-board .dest-option input:focus-visible", but its replacement ring`},
		// ---- 2. the ring token is read with its fallback ----
		{"global ring loses its fallback", portalFSEdit(a11y, replaceOnce(focusRingRef, "var(--p-focus-ring)")), `reads the ring token as "var(--p-focus-ring)"`},
		{"radio ring loses its fallback", portalFSEdit(a11y, func(s string) string {
			i := strings.LastIndex(s, focusRingRef)
			return s[:i] + "var(--p-focus-ring)" + s[i+len(focusRingRef):]
		}), `reads the ring token as "var(--p-focus-ring)"`},
		{"fallback to a token the old tokens.css lacks", portalFSEdit(a11y, replaceOnce(focusRingRef, "var(--p-focus-ring, var(--focus-ring))")), "reads the ring token as"},
		{"a pane reads the base --focus-ring directly", portalFSEdit("pane-home.tmpl", appendText(`<div style="outline: 2px solid var(--focus-ring)">x</div>`+"\n")), `reads the ring token as "var(--focus-ring)"`},
		// ---- 3. exactly one global ring, in the a11y partial ----
		{"a second global ring in css.tmpl", inCSS(":focus-visible { outline: 3px dotted var(--p-warn); }"), "found 2 global :focus-visible ring rule(s)"},
		{"the global ring is deleted", portalFSEdit(a11y, replaceOnce(globalRing, "")), "found 0 global :focus-visible ring rule(s)"},
		{"the global ring moves into css.tmpl", func(t *testing.T, m fstest.MapFS) {
			portalFSEdit(a11y, replaceOnce(globalRing, ""))(t, m)
			inCSS(strings.TrimSpace(globalRing))(t, m)
		}, "must be in " + portalA11yCSSPartial + " (the CSS partial served last), not css.tmpl"},
		{"the global ring only inside a media query", portalFSEdit(a11y, replaceOnce(globalRing, "  @media (min-width: 1px) {\n"+globalRing+"  }\n")), "is inside an at-rule"},
		// ---- 4. exactly one reduced-motion block, complete, in the a11y partial ----
		{"a second reduced-motion block in css.tmpl", inCSS("@media (prefers-reduced-motion: reduce) { #pane-story .x { animation: none; } }"), "found 2 @media (prefers-reduced-motion: reduce) block(s)"},
		{"the reduced-motion block is deleted", portalFSReplaceRe(a11y, rmBlockRe, "\n"), "found 0 @media (prefers-reduced-motion: reduce) block(s)"},
		{"the reduced-motion block moves into css.tmpl", func(t *testing.T, m fstest.MapFS) {
			portalFSReplaceRe(a11y, rmBlockRe, "\n")(t, m)
			inCSS("@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; animation-delay: 0s !important; animation-iteration-count: 1 !important; transition-duration: 0.01ms !important; transition-delay: 0s !important; scroll-behavior: auto !important; } }")(t, m)
		}, "the reduced-motion block must be in " + portalA11yCSSPartial},
		{"the reduced-motion block drops transition-duration", portalFSReplaceRe(a11y, `(?m)^\s*transition-duration: 0\.01ms !important;\n`, ""), "lacks transition-duration: 0.01ms !important"},
		{"the reduced-motion block keeps infinite iterations", portalFSEdit(a11y, replaceOnce("animation-iteration-count: 1 !important", "animation-iteration-count: infinite !important")), "lacks animation-iteration-count: 1 !important"},
		// ---- the scan itself ----
		{"no <style> element anywhere", func(t *testing.T, m fstest.MapFS) {
			for _, name := range []string{"css.tmpl", "css-avatar.tmpl", "css-profile.tmpl", a11y} {
				portalFSReplaceRe(name, `(?i)(</?)style\b`, "${1}div")(t, m)
			}
		}, "the a11y CSS gate would be scanning nothing"},
		{"a stylesheet the scan cannot parse", inCSS(".x { color: var(--p-text);"), "unclosed '{' in CSS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPortalA11yCSS(mutatedPortalFS(t, tc.mutate))
			if err == nil {
				t.Fatalf("check passed a mutated partial set; want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("check failed, but not for the mutation under test.\n got: %v\nwant substring: %q", err, tc.wantErr)
			}
		})
	}
}
