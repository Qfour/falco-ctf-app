package view

import (
	"encoding/json"
	"html/template"
)

// avatarURLsJSON returns the glyph -> URL object that portal.tmpl exposes as
// ASSETS.avatars. The URLs are the content-hashed served names from the static
// asset registry (ADR-0028), keyed by the glyph names of the avatar table
// (internal/scoreboard/avatar, ADR-0034 D9); the portal's JavaScript cannot
// call {{.Assets.URL}}, so it reads this map instead.
//
// A registry that cannot name a glyph is a build bug and already panics at
// start-up (avatarAssetSources); the error branches here are unreachable and
// degrade to an empty object rather than a broken page.
func avatarURLsJSON() template.JS {
	m, err := staticAssets.avatarURLs()
	if err != nil {
		return template.JS("{}")
	}
	b, err := json.Marshal(m)
	if err != nil { // a map[string]string cannot fail to marshal
		return template.JS("{}")
	}
	return template.JS(b)
}
