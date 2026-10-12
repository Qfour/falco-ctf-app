package view

import (
	"encoding/json"
	"html/template"
)

// avatarGlyphs are the picture files of the prepared avatars (ADR-0034 D9),
// in the contract's order. The glyph/colour table itself lives in
// internal/scoreboard/avatar; this package only needs the glyph names to build
// the URL map the portal's JavaScript draws from.
var avatarGlyphs = [...]string{"falcon", "shield", "key", "terminal", "radar", "lock", "bug", "flame"}

// avatarURLsJSON returns the glyph -> URL object that portal.tmpl exposes as
// ASSETS.avatars.
//
// STOPGAP until ADR-0028 (content-hash static assets) is merged with this
// branch: the URL is the fixed path /static/avatars/<glyph>.svg. When it
// lands, replace the body with a json.Marshal of staticAssets.avatarURLs()
// (same keys, served hashed URLs); nothing else in the portal changes.
func avatarURLsJSON() template.JS {
	m := make(map[string]string, len(avatarGlyphs))
	for _, g := range avatarGlyphs {
		m[g] = "/static/avatars/" + g + ".svg"
	}
	b, err := json.Marshal(m)
	if err != nil { // a map[string]string cannot fail to marshal
		return template.JS("{}")
	}
	return template.JS(b)
}
