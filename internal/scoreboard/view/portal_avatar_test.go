package view

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
)

// ADR-0034 S1 (D8/D9, V2/V4): the portal's profile form and avatar drawing.
// Source-text gates over the partials, in the style of portal_a11y_test.go:
// make test has no JS engine, so what the page DOES with the radio grid is
// pinned as text here and exercised with a DOM stub in the PR (see the PR body).
//
// What they guard:
//   - the glyph and colour lists the portal draws from are the contract's
//     (8 glyphs x 6 colours, internal/scoreboard/avatar is the Go source);
//   - an avatar is an <img> built by avatarImg() ONLY (no inline SVG, no
//     inline style attribute, no onerror=: all three are CSP-forbidden or
//     break D9 (c)), and every value it interpolates goes through esc();
//   - the colour reaches the <img> through an avatar-<color> class and one CSS
//     rule per colour in css-avatar.tmpl (design-engineer's partial);
//   - the picture URLs reach the script only through ASSETS.avatars, which the
//     server fills (portal.tmpl, portalData.AvatarURLsJSON);
//   - the profile form is a radiogroup of radios with an accessible name, and
//     saves through POST /api/users/{user}/profile;
//   - every display site (Me hero, Leaderboard rows / podium / result / mission
//     detail / live feed, Board thread messages) draws the avatar the API sent.

var (
	// The lists the portal must agree with come from the Go table, not from a
	// second literal here: a glyph or colour added to internal/scoreboard/avatar
	// alone fails this gate (the portal's JS arrays and css-avatar.tmpl are
	// hand-copied, ADR-0034 review R4#5), instead of silently drawing the
	// fallback.
	avatarContractGlyphs = avatar.GlyphNames()
	avatarContractColors = avatar.ColorNames()
	cssColorRuleAny      = regexp.MustCompile(`\.avatar-([a-z]+)\s*\{\s*background-color:\s*var\(--avatar-`)

	jsStrListRe  = func(name string) *regexp.Regexp { return regexp.MustCompile(`const ` + name + ` = \[([^\]]*)\];`) }
	jsQuotedRe   = regexp.MustCompile(`'([^']*)'`)
	avatarImgFn  = regexp.MustCompile(`(?s)const avatarImg = \(id, size\) => \{(.*?)\n\};`)
	avatarMarkup = regexp.MustCompile(`(?i)<img\b[^>]*\bclass\s*=\s*["']?avatar\b`)
	cssColorRule = func(c string) *regexp.Regexp {
		return regexp.MustCompile(`\.avatar-` + c + `\s*\{\s*background-color:\s*var\(--avatar-` + c + `\)`)
	}
)

func jsStringList(src, name string) ([]string, error) {
	m := jsStrListRe(name).FindStringSubmatch(src)
	if m == nil {
		return nil, fmt.Errorf("core-util.tmpl: const %s = [...] not found", name)
	}
	var out []string
	for _, q := range jsQuotedRe.FindAllStringSubmatch(m[1], -1) {
		out = append(out, q[1])
	}
	return out, nil
}

func sameList(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

// checkPortalAvatar runs every gate above over fsys and joins the failures.
func checkPortalAvatar(fsys fstest.MapFS) error {
	parts, err := readPortalPartials(fsys)
	if err != nil {
		return err
	}
	body := func(n string) string { return partialBody(parts, n) }
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	// ---- the table the portal draws from ----
	util := body("core-util.tmpl")
	if g, err := jsStringList(util, "AVATAR_GLYPHS"); err != nil {
		errs = append(errs, err)
	} else if !sameList(g, avatarContractGlyphs) {
		fail("core-util.tmpl: AVATAR_GLYPHS = %v, want %v (ADR-0034 D9; order is the grid's row order and the Go table's)", g, avatarContractGlyphs)
	}
	if c, err := jsStringList(util, "AVATAR_COLORS"); err != nil {
		errs = append(errs, err)
	} else if !sameList(c, avatarContractColors) {
		fail("core-util.tmpl: AVATAR_COLORS = %v, want %v", c, avatarContractColors)
	}
	// The operator's id is NOT named in any template: the picker takes its
	// choices from ASSETS.avatarChoices, so the rule has one home (avatar.StaffID).
	if strings.Contains(util, "AVATAR_STAFF_ID") || strings.Contains(util, avatar.StaffID) {
		fail("core-util.tmpl names the operator's avatar (AVATAR_STAFF_ID / %q) — the picker must read ASSETS.avatarChoices instead", avatar.StaffID)
	}
	if strings.Contains(util, "AVATAR_SRC") || regexp.MustCompile(`/static/avatars`).MatchString(util) {
		fail("core-util.tmpl hard-codes an avatar URL — URLs come from ASSETS.avatars (portal.tmpl), which the server fills from the static-asset registry")
	}
	root := body("portal.tmpl")
	if !regexp.MustCompile(`const ASSETS = Object\.freeze\(\{ avatars: Object\.freeze\(\{\{\.AvatarURLsJSON\}\}\), avatarChoices: Object\.freeze\(\{\{\.AvatarChoicesJSON\}\}\) \}\);`).MatchString(root) {
		fail("portal.tmpl: no `const ASSETS = Object.freeze({ avatars: ... {{.AvatarURLsJSON}} ..., avatarChoices: ... {{.AvatarChoicesJSON}} ... })` — avatarImg() reads its URLs from there and the picker its choices")
	}

	// ---- avatarImg(): esc() on every interpolation, no style/onerror ----
	fn := avatarImgFn.FindStringSubmatch(util)
	if fn == nil {
		fail("core-util.tmpl: avatarImg(id, size) not found")
	} else {
		// Every operand of the string concatenation that is not a literal must
		// be wrapped in esc(): cls, the src lookup, glyph, colour.
		for _, want := range []string{`esc(cls)`, `esc(src)`, `esc(p.color)`} {
			if !strings.Contains(fn[1], want) {
				fail("core-util.tmpl: avatarImg() no longer interpolates %s — every value that reaches the markup goes through esc() (no exemption by origin)", want)
			}
		}
		if !strings.Contains(fn[1], `' avatar-' + esc(p.color)`) || !strings.Contains(fn[1], `alt=""`) {
			fail("core-util.tmpl: avatarImg() must emit the avatar-<color> class and an empty alt")
		}
		if !strings.Contains(fn[1], `AVATAR_GLYPHS.includes(p.glyph)`) {
			fail("core-util.tmpl: avatarImg() must take the URL only for a glyph in the table (AVATAR_GLYPHS.includes)")
		}
		if regexp.MustCompile(`(?i)\bstyle\s*=|\bon[a-z]+\s*=`).MatchString(fn[1]) {
			fail("core-util.tmpl: avatarImg() emits a style= or on*= attribute — CSP forbids both, and the colour comes from data-color + css-avatar.tmpl")
		}
	}

	// ---- an avatar <img> is written in exactly one place; no inline SVG ----
	for _, p := range parts {
		stripped := p.body
		if p.name == "core-util.tmpl" {
			// the one definition (avatarImg) and its comment
			stripped = avatarImgFn.ReplaceAllString(stripped, "")
		}
		// css-avatar.tmpl's comment shows the markup it styles; CSS partials hold no HTML.
		if !strings.HasPrefix(p.name, "css") && avatarMarkup.MatchString(stripped) {
			fail("%s writes an <img class=\"avatar\"> itself — draw avatars with avatarImg() only", p.name)
		}
		if p.name != "css-avatar.tmpl" && regexp.MustCompile(`(?i)<svg\b`).MatchString(stripped) {
			fail("%s contains an inline <svg> — avatars are <img> of a static asset (ADR-0034 D9 (c))", p.name)
		}
	}

	// ---- colour rules ----
	css := body("css-avatar.tmpl")
	if css == "" {
		fail("css-avatar.tmpl is not a partial — the avatar CSS lives there")
	}
	for _, c := range avatarContractColors {
		if !cssColorRule(c).MatchString(css) {
			fail("css-avatar.tmpl: no `.avatar-%s { background-color: var(--avatar-%s) }` rule", c, c)
		}
	}
	// ...and no colour rule the table does not name (a stale class would look
	// valid but never be reached).
	var cssColors []string
	for _, m := range cssColorRuleAny.FindAllStringSubmatch(css, -1) {
		cssColors = append(cssColors, m[1])
	}
	if !sameList(cssColors, avatarContractColors) {
		fail("css-avatar.tmpl: .avatar-<color> rules = %v, want avatar.ColorNames() = %v", cssColors, avatarContractColors)
	}
	prof := body("css-profile.tmpl")
	for _, sel := range []string{".avatar-sm {", ".avatar-lg {", ".with-avatar {"} {
		if !strings.Contains(prof, sel) {
			fail("css-profile.tmpl: no %q rule", sel)
		}
	}

	// ---- display sites ----
	for _, site := range []struct{ partial, want, why string }{
		{"pane-me.tmpl", `avatarImg(d.avatar, 'lg')`, "Me hero (replaces avatarChar)"},
		{"pane-scoreboard.tmpl", `avatarImg(p.avatar, 'sm')`, "Leaderboard rows / Result table (LeaderboardEntry.avatar)"},
		{"pane-scoreboard.tmpl", `avatarImg(p.avatar, 'lg')`, "Result podium"},
		{"pane-scoreboard.tmpl", `avatarImg(s.avatar, 'sm')`, "mission detail (ChallengeSolver) and live feed (SolveRecord)"},
		{"pane-board.tmpl", `avatarImg(m.authorAvatar, 'sm')`, "Board thread messages (BoardMessage.authorAvatar)"},
	} {
		if !strings.Contains(body(site.partial), site.want) {
			fail("%s no longer draws %s — %s", site.partial, site.want, site.why)
		}
	}
	if strings.Contains(body("pane-me.tmpl"), "avatarChar") {
		fail("pane-me.tmpl still has avatarChar — the initial-letter avatar is replaced by the picture")
	}
	if n := strings.Count(body("pane-scoreboard.tmpl"), "avatarImg(p.avatar, 'sm')"); n != 2 {
		fail("pane-scoreboard.tmpl draws avatarImg(p.avatar, 'sm') %d time(s), want 2 (Leaderboard rows + Result table: LeaderboardEntry.avatar)", n)
	}
	if n := strings.Count(body("pane-scoreboard.tmpl"), "avatarImg(s.avatar, 'sm')"); n != 2 {
		fail("pane-scoreboard.tmpl draws avatarImg(s.avatar, 'sm') %d time(s), want 2 (mission detail + live feed)", n)
	}
	if n := strings.Count(body("pane-board.tmpl"), "avatarImg(m.authorAvatar, 'sm')"); n != 2 {
		fail("pane-board.tmpl draws avatarImg(m.authorAvatar, 'sm') %d time(s), want 2 (participant thread + operator thread)", n)
	}

	// ---- the profile form ----
	me := body("pane-me.tmpl")
	for _, want := range []struct{ text, why string }{
		{`role="radiogroup" aria-labelledby="pane-me-profile-avatar-label"`, "the grid is a radiogroup with an accessible name"},
		{`role="radio" aria-checked="false" tabindex="-1"`, "each option is a radio with a roving tabindex"},
		{`aria-label="' + esc(optLabel(id)) + '"`, "each radio's name is its glyph and colour (esc'd)"},
		{`Array.isArray(ASSETS.avatarChoices)) ? ASSETS.avatarChoices : []`, "the picker's choices are the server's ASSETS.avatarChoices"},
		{`const pickable = (id) => AVATAR_CHOICES.includes(id);`, "a grid id outside the choices (the operator's fixed avatar) is not pickable: it is a disabled radio"},
		{`' aria-disabled="true"'`, "the staff radio is aria-disabled"},
		{`: staff only'`, "the staff radio says it is staff only"},
		{`if (saving || serverSig === null) return;`, "submit is refused before the first /me answer"},
		{`saveBtn.disabled = saving || !loaded;`, "Save is disabled until the first /me answer has filled the form"},
		{`id="pane-me-profile-save" disabled aria-describedby="pane-me-profile-save-help"`, "Save starts disabled and says why"},
		{`case 'ArrowRight'`, "keyboard: arrows"}, {`case 'ArrowLeft'`, "keyboard: arrows"},
		{`case 'ArrowDown'`, "keyboard: arrows"}, {`case 'ArrowUp'`, "keyboard: arrows"},
		{`case 'Home'`, "keyboard: Home"}, {`case 'End'`, "keyboard: End"},
		{`'/api/users/' + encodeURIComponent(user) + '/profile'`, "saves through POST /api/users/{user}/profile (D8)"},
		{`method: 'POST'`, "POST"},
		{`body.display_name = name`, "payload carries display_name"},
		{`body.avatar = chosen`, "payload carries avatar"},
		{`announce('Profile saved.`, "success is announced once through the live region"},
		{`r.status === 400`, "400 gets a sentence"}, {`r.status === 403`, "403 gets a sentence"}, {`r.status === 429`, "429 gets a sentence"},
		{`for="pane-me-profile-name"`, "the name input has a <label for>"},
	} {
		if !strings.Contains(me, want.text) {
			fail("pane-me.tmpl: missing %q — %s", want.text, want.why)
		}
	}
	// The form is built once outside the polled container: it must not be in
	// the template literal that render() assigns to #pane-me-page.
	if strings.Contains(me, "id=\"pane-me-profile-form\"") && strings.Index(me, "id=\"pane-me-profile\"") > strings.Index(me, `<script nonce`) {
		fail("pane-me.tmpl: the profile section must be markup BEFORE the script (static, outside the polled #pane-me-page)")
	}
	if regexp.MustCompile("(?s)pane-me-page'\\)\\.innerHTML = `[^`]*pane-me-profile").MatchString(me) {
		fail("pane-me.tmpl: the profile form is inside the template literal that is re-rendered every 2 s — it would lose focus and typed text on every poll")
	}
	// The error text is written with textContent, never as markup.
	if regexp.MustCompile(`msgEl\.innerHTML`).MatchString(me) {
		fail("pane-me.tmpl: the profile message is set through innerHTML — it carries server text; use textContent")
	}
	return errors.Join(errs...)
}

func TestPortalAvatar_ContractAndDisplaySites(t *testing.T) {
	m := mutatedPortalFS(t, func(*testing.T, fstest.MapFS) {})
	if err := checkPortalAvatar(m); err != nil {
		t.Error(err)
	}
}

// TestPortalAvatar_ChecksRejectMutations: each case breaks ONE thing and the
// gate must name it. The unmutated copy passes (above), so a failure here is
// the mutation.
func TestPortalAvatar_ChecksRejectMutations(t *testing.T) {
	const util = "core-util.tmpl"
	const me = "pane-me.tmpl"
	cases := []struct {
		name   string
		mutate func(*testing.T, fstest.MapFS)
		want   string
	}{
		{"core-util names the staff avatar again", portalFSEdit(util, replaceOnce("const AVATAR_FALLBACK", "const AVATAR_STAFF_ID = '"+avatar.StaffID+"';\nconst AVATAR_FALLBACK")), "names the operator's avatar"},
		{"a glyph is dropped from the table", portalFSEdit(util, replaceOnce("'bug', 'flame'];", "'flame'];")), "AVATAR_GLYPHS"},
		{"a colour is renamed", portalFSEdit(util, replaceOnce("'violet', 'slate'];", "'purple', 'slate'];")), "AVATAR_COLORS"},
		{"avatarImg hard-codes a URL", portalFSEdit(util, replaceOnce("const AVATAR_COLORS", "const AVATAR_SRC = { falcon: '/static/avatars/falcon.svg' };\nconst AVATAR_COLORS")), "hard-codes an avatar URL"},
		{"ASSETS is no longer declared in the root", portalFSEdit("portal.tmpl", replaceOnce("const ASSETS = ", "const ASSETZ = ")), "const ASSETS"},
		{"avatarImg stops escaping the colour", portalFSEdit(util, replaceOnce(`esc(p.color)`, `p.color`)), "esc(p.color)"},
		{"avatarImg stops escaping the src", portalFSEdit(util, replaceOnce(`esc(src)`, `src`)), "esc(src)"},
		{"avatarImg takes a URL for any glyph", portalFSEdit(util, replaceOnce(`AVATAR_GLYPHS.includes(p.glyph) && typeof`, `typeof`)), "AVATAR_GLYPHS.includes"},
		{"avatarImg gains an inline style", portalFSEdit(util, replaceOnce(`alt="" width`, `alt="" style="background:red" width`)), "style= or on*="},
		{"avatarImg gains an onerror handler", portalFSEdit(util, replaceOnce(`alt="" width`, `alt="" onerror="x()" width`)), "style= or on*="},
		{"a pane writes the <img> itself", portalFSEdit("pane-scoreboard.tmpl", replaceOnce(`${avatarImg(p.avatar, 'lg')}`, `<img class="avatar" src="/static/avatars/${p.avatar}.svg">`)), "writes an <img class=\"avatar\"> itself"},
		{"inline SVG in a pane", portalFSEdit("pane-board.tmpl", appendText("<svg viewBox=\"0 0 1 1\"></svg>\n")), "inline <svg>"},
		{"a colour rule is gone", portalFSEdit("css-avatar.tmpl", replaceOnce(`.avatar-lime `, `.avatar-green `)), "no `.avatar-lime"},
		{"the Me hero goes back to the initial letter", portalFSEdit(me, replaceOnce(`${avatarImg(d.avatar, 'lg')}`, `<div class="avatar">${avatarChar(displayName)}</div>`)), "avatarChar"},
		{"the leaderboard stops drawing avatars", portalFSEdit("pane-scoreboard.tmpl", replaceOnce(`avatarImg(p.avatar, 'sm')`, `''`)), "Leaderboard rows"},
		{"the board stops drawing authorAvatar (operator thread)", portalFSEdit("pane-board.tmpl", func(s string) string {
			i := strings.LastIndex(s, "avatarImg(m.authorAvatar, 'sm')")
			return s[:i] + "''" + s[i+len("avatarImg(m.authorAvatar, 'sm')"):]
		}), "participant thread + operator thread"},
		{"the staff avatar becomes a choice", portalFSEdit(me, replaceOnce(`AVATAR_CHOICES.includes(id)`, `true`)), "not pickable"},
		{"the picker stops reading ASSETS.avatarChoices", portalFSEdit(me, replaceOnce(`Array.isArray(ASSETS.avatarChoices)) ? ASSETS.avatarChoices : []`, `[]`)), "ASSETS.avatarChoices"},
		{"Save is enabled before the first /me", portalFSEdit(me, replaceOnce(`saving || !loaded`, `saving`)), "disabled until the first /me"},
		{"the grid loses its radiogroup role", portalFSEdit(me, replaceOnce(`role="radiogroup"`, ``)), "radiogroup"},
		{"ArrowUp is no longer handled", portalFSEdit(me, replaceOnce(`case 'ArrowUp'`, `case 'KeyU'`)), "case 'ArrowUp'"},
		{"saving posts to another route", portalFSEdit(me, replaceOnce(`+ '/profile'`, `+ '/display-name'`)), "/profile"},
		{"the 429 sentence is dropped", portalFSEdit(me, replaceOnce(`r.status === 429`, `r.status === 428`)), "429"},
		{"the message is written as markup", portalFSEdit(me, replaceOnce(`msgEl.textContent = text;`, `msgEl.innerHTML = text;`)), "innerHTML"},
		{"the form moves into the polled template literal", portalFSEdit(me, replaceOnce("document.getElementById('pane-me-page').innerHTML = `\n      <section class=\"ident\">", "document.getElementById('pane-me-page').innerHTML = `\n      <div id=\"pane-me-profile\"></div><section class=\"ident\">")), "re-rendered every 2 s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkPortalAvatar(mutatedPortalFS(t, c.mutate))
			if err == nil {
				t.Fatal("the gate passed a mutated partial")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the gate failed, but not on the mutation: got %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestPortalAvatar_ServedURLMap: the served portal declares ASSETS.avatars with
// exactly the eight glyphs, each pointing at a same-origin /static/ .svg, in the
// script that comes before every pane (so avatarImg can read it).
func TestPortalAvatar_ServedURLMap(t *testing.T) {
	w := httptest.NewRecorder()
	if err := renderPortal(w, httptest.NewRequest("GET", "/portal", nil), nil, nil, ""); err != nil {
		t.Fatalf("renderPortal: %v", err)
	}
	body := w.Body.String()
	m := regexp.MustCompile(`const ASSETS = Object\.freeze\(\{ avatars: Object\.freeze\((\{[^}]*\})\), avatarChoices: Object\.freeze\((\[[^\]]*\])\) \}\);`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the served portal has no ASSETS.avatars / ASSETS.avatarChoices declaration")
	}
	// ASSETS.avatarChoices is what a participant can pick: the table without the
	// operator's fixed StaffID, in table order (ADR-0034 D8). The picker draws
	// these; the profile API refuses any other.
	var choices []string
	if err := json.Unmarshal([]byte(m[2]), &choices); err != nil {
		t.Fatalf("ASSETS.avatarChoices is not a JSON array: %v (%s)", err, m[2])
	}
	if !sameList(choices, avatar.ParticipantIDs()) {
		t.Errorf("ASSETS.avatarChoices = %v, want avatar.ParticipantIDs() = %v", choices, avatar.ParticipantIDs())
	}
	if len(choices) != avatar.ParticipantCount {
		t.Errorf("ASSETS.avatarChoices has %d ids, want %d", len(choices), avatar.ParticipantCount)
	}
	// The picker draws the whole table (the 8 x 6 shape) and disables whatever
	// is not in avatarChoices, so "disabled radios" == table minus choices must
	// be exactly the operator's id, and nothing outside the table may be offered.
	inChoices := map[string]bool{}
	for _, id := range choices {
		inChoices[id] = true
	}
	var disabled []string
	for _, id := range avatar.IDs() {
		if !inChoices[id] {
			disabled = append(disabled, id)
		}
		delete(inChoices, id)
	}
	if !sameList(disabled, []string{avatar.StaffID}) {
		t.Errorf("table minus ASSETS.avatarChoices = %v, want just the operator's %s (the one disabled radio)", disabled, avatar.StaffID)
	}
	if len(inChoices) != 0 {
		t.Errorf("ASSETS.avatarChoices offers ids outside the table: %v", inChoices)
	}
	for _, id := range choices {
		if id == avatar.StaffID {
			t.Errorf("ASSETS.avatarChoices offers the operator's fixed %s", id)
		}
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(m[1]), &got); err != nil {
		t.Fatalf("ASSETS.avatars is not a JSON object: %v (%s)", err, m[1])
	}
	if len(got) != len(avatarContractGlyphs) {
		t.Errorf("ASSETS.avatars has %d glyphs, want %d: %v", len(got), len(avatarContractGlyphs), got)
	}
	for _, g := range avatarContractGlyphs {
		u := got[g]
		if !strings.HasPrefix(u, "/static/") || !strings.HasSuffix(u, ".svg") || !strings.Contains(u, g) || strings.Contains(u, "..") {
			t.Errorf("ASSETS.avatars[%s] = %q, want a same-origin /static/…%s….svg path", g, u, g)
		}
	}
	if i, j := strings.Index(body, "const ASSETS"), strings.Index(body, "const esc"); i < 0 || j < 0 || i > j {
		t.Errorf("ASSETS must be declared before core-util's script (index %d vs %d)", i, j)
	}
}
