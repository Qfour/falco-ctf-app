package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrFlagOverrides wraps every rejection of a flags file, so the caller can
// tell "the flags file is unusable" apart from a catalog/scenario load error.
var ErrFlagOverrides = errors.New("flag overrides rejected")

// flagIDRE is the shape of a challengeId as it may appear as a key in a flags
// file. A key outside this shape is never echoed in an error (a line with key
// and value swapped would otherwise put a flag value in the log).
var flagIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Scored is the catalog a scoreboard instance scores, plus the scenario it
// was scoped to.
type Scored struct {
	// Catalog holds only the challenges in scope, with per-event flags
	// applied when a flags file was given.
	Catalog Catalog
	// ScenarioID is the pinned scenario's id, "" when none is pinned.
	ScenarioID string
	// Order is the mission sequence: the scenario's explicit order, or the
	// catalog's sorted ids when no scenario is pinned.
	Order []string
}

// LoadScored builds the catalog the scoreboard scores, in one step: load
// challengesDir, restrict to scenarioFile's challenges (when set), then apply
// flagsFile (when set). It is the only entry point for per-event flags, so
// the scenario restriction and the flag override cannot be wired in the wrong
// order or against the wrong catalog by a caller.
//
// A flags-file rejection is wrapped in ErrFlagOverrides.
func LoadScored(challengesDir, scenarioFile, flagsFile string) (Scored, error) {
	full, err := Load(challengesDir)
	if err != nil {
		return Scored{}, fmt.Errorf("catalog load %q: %w", challengesDir, err)
	}
	var out Scored
	var ids []string // nil = every challenge
	if scenarioFile != "" {
		sc, err := LoadScenario(scenarioFile)
		if err != nil {
			return Scored{}, fmt.Errorf("scenario load %q: %w", scenarioFile, err)
		}
		ids = sc.Challenges
		out.ScenarioID = sc.ID
	}
	if out.Catalog, err = full.scored(ids, flagsFile); err != nil {
		return Scored{}, err
	}
	if ids != nil {
		out.Order = ids
	} else {
		out.Order = out.Catalog.IDs()
	}
	return out, nil
}

// scored returns a NEW catalog holding the challenges named by ids (nil =
// all of c), with the per-event flags from flagsPath applied. c itself is
// never modified and keeps the repository defaults.
//
// The public repo's falco-rule.yaml carries only FALCO{dev-...} placeholders;
// real flags are injected at deploy time from a mounted secret (rendered from
// falco-ctf-platform's events/<date>/flags.sops.yaml). The planting side
// (charts/ctf-user/validate-flags-file.sh, called by deploy-user.sh
// --flags-file) pre-checks the same file before it touches a cluster; this
// function is the authority on what is scored. The two are kept in step by
// the shared cases in testdata/flags-parity.
//
// Fail-closed — when flagsPath is set, each of these is an error and no flag
// is applied:
//   - the file is unreadable, not a single YAML document, or has no
//     top-level `flags:` mapping with at least one entry
//   - a key is not shaped like a challengeId, or appears twice
//   - an entry names a challenge that is not in c, or is not evade
//   - a value is not a scalar written literally on the same line as its key
//     (no escapes, block/flow/multi-line forms or aliases), or does not match
//     FALCO{...} (only A-Za-z0-9_- inside the braces)
//   - a value equals the repository default of ANY challenge
//   - two entries carry the same value
//   - an evade challenge in scope has no entry (it would otherwise keep
//     being scored against the repository default)
//
// One event file serves every scenario: an entry for an evade challenge
// outside ids is validated but not applied.
//
// Error messages name challenge ids and line numbers only, never a flag
// value or any other unvalidated text from the file.
//
// An empty flagsPath applies nothing (local dev / tests run against the
// placeholders).
func (c Catalog) scored(ids []string, flagsPath string) (Catalog, error) {
	out := make(Catalog, len(c))
	if ids == nil {
		for id, ch := range c {
			out[id] = ch
		}
	} else {
		r, err := c.Restrict(ids)
		if err != nil {
			return nil, err
		}
		out = r
	}
	if flagsPath == "" {
		return out, nil
	}
	reject := func(format string, args ...any) (Catalog, error) {
		return nil, fmt.Errorf("%w: flags file %q: %s", ErrFlagOverrides, flagsPath, fmt.Sprintf(format, args...))
	}

	entries, err := readFlagsFile(flagsPath)
	if err != nil {
		return reject("%s", err)
	}

	// Validate every entry against the full catalog before applying any.
	// entries are in file order, so the first reported problem is stable.
	byValue := make(map[string]string, len(entries)) // value -> id that carries it
	supplied := make(map[string]string, len(entries))
	for _, e := range entries {
		ch, ok := c[e.id]
		if !ok {
			return reject("unknown challengeId %q", e.id)
		}
		if ch.Type != "evade" {
			return reject("challenge %q is type %q, only evade challenges have flags", e.id, ch.Type)
		}
		if !flagRE.MatchString(e.value) {
			return reject("flag for %q must match FALCO{...} (only A-Za-z0-9_- inside the braces)", e.id)
		}
		for _, other := range c.IDs() {
			if c[other].Type == "evade" && c[other].ExpectedFlag == e.value {
				return reject("flag for %q is the same as a repository default (of %q); supply a per-event value", e.id, other)
			}
		}
		if first, dup := byValue[e.value]; dup {
			return reject("flag for %q is the same as the flag for %q; every challenge needs its own value", e.id, first)
		}
		byValue[e.value] = e.id
		supplied[e.id] = e.value
	}

	var missing []string
	for id, ch := range out {
		if ch.Type != "evade" {
			continue
		}
		if _, ok := supplied[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return reject("no flag supplied for evade challenge(s) in scope: %s", strings.Join(missing, ", "))
	}

	for id, value := range supplied {
		ch, inScope := out[id]
		if !inScope {
			continue
		}
		ch.ExpectedFlag = value
		out[id] = ch
	}
	return out, nil
}

type flagEntry struct {
	id    string
	value string
}

// readFlagsFile parses the `{flags: {<challengeId>: <flag>}}` file into
// entries in file order. It works on yaml.Node rather than a typed struct so
// that it can (1) reject duplicate keys and extra documents itself instead of
// relying on decoder defaults, (2) require each value to be written literally
// on the same line as its key (no escapes, block scalars, flow mappings or
// aliases — forms the planting side's line-based reader cannot see the same
// way), and (3) report
// line numbers without ever quoting file content. Returned errors are safe to
// log.
func readFlagsFile(path string) ([]flagEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// *PathError: names the path and the OS reason, no file content.
		return nil, fmt.Errorf("read: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("no flags found under top-level `flags:` key")
		}
		// yaml's own message is dropped: it is not needed to find the
		// problem and is not guaranteed to be free of file content.
		return nil, errors.New("not valid YAML")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("must be a single YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("top level must be a mapping with a `flags:` key")
	}
	root := doc.Content[0]
	var flags *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if k := root.Content[i]; k.Kind == yaml.ScalarNode && k.Value == "flags" {
			if flags != nil {
				return nil, fmt.Errorf("line %d: `flags:` appears more than once", k.Line)
			}
			flags = root.Content[i+1]
		}
	}
	if flags == nil || flags.Kind != yaml.MappingNode || len(flags.Content) == 0 {
		return nil, errors.New("no flags found under top-level `flags:` key")
	}
	if flags.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("line %d: `flags:` must be a block mapping, one entry per line", flags.Line)
	}

	lines := strings.Split(string(data), "\n")
	seen := make(map[string]bool, len(flags.Content)/2)
	entries := make([]flagEntry, 0, len(flags.Content)/2)
	for i := 0; i+1 < len(flags.Content); i += 2 {
		k, v := flags.Content[i], flags.Content[i+1]
		if k.Kind != yaml.ScalarNode || !flagIDRE.MatchString(k.Value) {
			return nil, fmt.Errorf("line %d: malformed entry (key is not a challengeId)", k.Line)
		}
		id := k.Value
		if seen[id] {
			return nil, fmt.Errorf("line %d: challengeId %q appears more than once", k.Line, id)
		}
		seen[id] = true
		if v.Kind != yaml.ScalarNode || v.Line != k.Line || v.Line < 1 || v.Line > len(lines) || v.Value == "" ||
			!strings.Contains(lines[v.Line-1], v.Value) {
			return nil, fmt.Errorf("line %d: flag for %q must be a plain string written literally on the same line", k.Line, id)
		}
		entries = append(entries, flagEntry{id: id, value: v.Value})
	}
	return entries, nil
}
