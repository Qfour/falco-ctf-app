// Package challengeid is the ONE definition of what a challenge id may look like
// (app#437). A challenge's id is its directory name under challenges/: two digits,
// a hyphen, then a lower-case slug.
//
// It is a leaf on purpose: standard library only. internal/catalog imports
// gopkg.in/yaml.v3, and the collector (a distroless image whose SBOM carries
// only what runs) must be able to use the grammar without linking the catalog
// parser or yaml.v3 (internal/apispec/dependency_boundary_test.go fixes that).
// Its users are catalog.Load (which refuses to start on a directory outside the
// grammar), the scoreboard's {cid} check, the collector's {cid} check, the flags
// file's challengeId key, and the Home-fragment generator's directory scan.
package challengeid

import "regexp"

// Pattern is the grammar, as the string the OpenAPI specs repeat (`Cid.pattern`).
const Pattern = `^[0-9]{2}-[a-z0-9-]{1,60}$`

var re = regexp.MustCompile(Pattern)

// Valid reports whether id is a challenge id.
func Valid(id string) bool { return re.MatchString(id) }

// Unknown is the single metric-label / log value every id that is not a catalog
// key is folded into (the scoreboard's closed label set). It must stay OUTSIDE the
// grammar, so that it can never be the id of a real challenge (TestUnknownIsNotAnID).
const Unknown = "_unknown"
