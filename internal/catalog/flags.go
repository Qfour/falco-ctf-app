package catalog

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// flagOverrides is the on-disk shape of the FLAGS_FILE secret: a map of
// challengeId -> flag. It deliberately mirrors the planting side
// (charts/ctf-user/deploy-user.sh --flags-file reads the same shape and
// applies the same validation, see charts/ctf-user/validate-flags-file.sh) so
// the scored flag and the planted flag always agree.
type flagOverrides struct {
	Flags map[string]string `yaml:"flags"`
}

// ApplyFlagOverrides replaces the placeholder expectedFlag of the evade
// challenges in c with the real per-event flags read from path.
//
// The public repo's falco-rule.yaml carries only FALCO{dev-...} placeholders;
// real flags are injected at deploy time from a mounted secret (rendered from
// falco-ctf-platform's events/<date>/flags.sops.yaml).
//
// c is the catalog the scoreboard will actually score (after any scenario
// Restrict). known is the full, unrestricted catalog as loaded from disk, with
// its expectedFlag values still at the repository defaults; pass c itself when
// no scenario is pinned. The two are separate so that one event flags file can
// be reused across scenarios: an entry for a challenge outside the pinned
// scenario is validated but not applied.
//
// Fail-closed — when path is set, every one of these is an error and nothing
// is applied:
//   - the file is unreadable, unparsable, or has no entries under `flags:`
//   - an entry names a challengeId that is not in known, or is not evade
//   - an entry's value does not match FALCO{...}
//   - an entry's value equals the repository default for that challenge
//     (the flag was not rotated for the event)
//   - an evade challenge in c has no entry (it would otherwise keep being
//     scored against the repository default)
//
// Error messages name challenge ids only, never flag values.
//
// An empty path is a no-op (local dev / tests run against the placeholders).
func (c Catalog) ApplyFlagOverrides(path string, known Catalog) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read flags file %q: %w", path, err)
	}
	var ov flagOverrides
	if err := yaml.Unmarshal(data, &ov); err != nil {
		return fmt.Errorf("parse flags file %q: %w", path, err)
	}
	if len(ov.Flags) == 0 {
		return fmt.Errorf("flags file %q: no flags found under top-level `flags:` key", path)
	}

	// Validate every entry before touching c, in a stable order so the
	// reported error does not depend on map iteration.
	supplied := make([]string, 0, len(ov.Flags))
	for id := range ov.Flags {
		supplied = append(supplied, id)
	}
	sort.Strings(supplied)
	for _, id := range supplied {
		flag := ov.Flags[id]
		ch, ok := known[id]
		if !ok {
			return fmt.Errorf("flags file %q: unknown challengeId %q", path, id)
		}
		if ch.Type != "evade" {
			return fmt.Errorf("flags file %q: challenge %q is type %q, only evade challenges have flags", path, id, ch.Type)
		}
		if !flagRE.MatchString(flag) {
			return fmt.Errorf("flags file %q: flag for %q must match FALCO{...}", path, id)
		}
		if flag == ch.ExpectedFlag {
			return fmt.Errorf("flags file %q: flag for %q is the same as the repository default; supply a per-event value", path, id)
		}
	}

	var missing []string
	for id, ch := range c {
		if ch.Type != "evade" {
			continue
		}
		if _, ok := ov.Flags[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("flags file %q: no flag supplied for evade challenge(s) in scope: %s", path, strings.Join(missing, ", "))
	}

	for _, id := range supplied {
		ch, inScope := c[id]
		if !inScope {
			continue
		}
		ch.ExpectedFlag = ov.Flags[id]
		c[id] = ch
	}
	return nil
}
