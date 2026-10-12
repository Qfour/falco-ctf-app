package view

import (
	"encoding/json"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
)

// TestAvatarAssets_MatchAvatarTable is the table-vs-assets agreement for
// ADR-0034 D9. The avatar package is the one table that validates an id; the
// view package owns the files and tokens.css. This pins, from the table
// outward, that every glyph the table can name has a registered file and every
// colour has a --avatar-<color> token, with nothing extra on either side —
// so a glyph/colour added to one side alone fails here instead of rendering a
// broken image for a valid id.
func TestAvatarAssets_MatchAvatarTable(t *testing.T) {
	if got, want := avatarAssetGlyphs, avatar.GlyphNames(); !equalAsSets(got, want) {
		t.Fatalf("registered avatar glyphs = %v, want avatar.GlyphNames() = %v", got, want)
	}

	// Every glyph name in the table resolves to a served URL.
	urls, err := staticAssets.avatarURLs()
	if err != nil {
		t.Fatal(err)
	}
	var urlGlyphs []string
	for g := range urls {
		urlGlyphs = append(urlGlyphs, g)
	}
	if !equalAsSets(urlGlyphs, avatar.GlyphNames()) {
		t.Fatalf("avatarURLs() keys = %v, want avatar.GlyphNames() = %v", urlGlyphs, avatar.GlyphNames())
	}

	// Every id's file is one of those glyph files.
	for _, id := range avatar.IDs() {
		f, ok := avatar.File(id)
		if !ok {
			t.Fatalf("avatar.File(%q) not ok for a table id", id)
		}
		if _, err := avatarFS.ReadFile("static/avatars/" + f); err != nil {
			t.Errorf("id %q: file %s is not embedded: %v", id, f, err)
		}
	}

	// Every colour in the table has its token in tokens.css, and tokens.css has
	// no colour the table does not name.
	tokens := avatarTokenValues(t)
	var tokenColors []string
	for c := range tokens {
		tokenColors = append(tokenColors, c)
	}
	if !equalAsSets(tokenColors, avatar.ColorNames()) {
		t.Errorf("tokens.css --avatar-<color> = %v, want avatar.ColorNames() = %v", tokenColors, avatar.ColorNames())
	}
	for _, id := range avatar.IDs() {
		tok, _ := avatar.ColorToken(id)
		if _, ok := tokens[tok[len(avatar.ColorTokenPrefix):]]; !ok {
			t.Errorf("id %q: tokens.css defines no %s", id, tok)
		}
	}
}

// TestAvatarURLsJSON_IsTheRegistry: the ASSETS.avatars object the portal
// serializes is the registry's content-hashed URL map, not a fixed path.
func TestAvatarURLsJSON_IsTheRegistry(t *testing.T) {
	want, err := staticAssets.avatarURLs()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(avatarURLsJSON()), &got); err != nil {
		t.Fatalf("avatarURLsJSON is not a JSON object: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("avatarURLsJSON has %d entries, want %d", len(got), len(want))
	}
	for g, u := range want {
		if got[g] != u {
			t.Errorf("%s: avatarURLsJSON = %q, want the registry's %q", g, got[g], u)
		}
	}
}
