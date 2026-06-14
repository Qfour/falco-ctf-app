package catalog

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// flagOverrides is the on-disk shape of the FLAGS_FILE secret: a map of
// challengeId -> flag. It deliberately mirrors the planting side
// (challenges/<NN>/plant.sh reads CTF_FLAG_<ID> from the same source) so the
// scored flag and the planted flag always agree.
type flagOverrides struct {
	Flags map[string]string `yaml:"flags"`
}

// ApplyFlagOverrides replaces the placeholder expectedFlag of evade challenges
// with the real per-event flags read from path.
//
// The public repo's falco-rule.yaml carries only FALCO{dev-...} placeholders;
// real flags are injected at deploy time from a mounted secret (rendered from
// falco-ctf-platform's events/<date>/flags.sops.yaml). Fail-closed: an unknown
// challengeId, a malformed flag, or an override targeting a non-evade challenge
// is an error so a misconfigured secret is loud rather than silently scoring
// against a dev placeholder.
//
// An empty path is a no-op (local dev / tests run against the placeholders).
func (c Catalog) ApplyFlagOverrides(path string) error {
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
	for id, flag := range ov.Flags {
		ch, ok := c[id]
		if !ok {
			return fmt.Errorf("flags file %q: unknown challengeId %q", path, id)
		}
		if ch.Type != "evade" {
			return fmt.Errorf("flags file %q: challenge %q is type %q, only evade challenges have flags", path, id, ch.Type)
		}
		if !flagRE.MatchString(flag) {
			return fmt.Errorf("flags file %q: flag for %q must match FALCO{...}", path, id)
		}
		ch.ExpectedFlag = flag
		c[id] = ch
	}
	return nil
}
