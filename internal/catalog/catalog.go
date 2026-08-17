// Package catalog loads challenge metadata from `challenges/<NN>-<slug>/falco-rule.yaml`.
//
// Schema:
//
//	challengeId:   string (defaults to directory name)
//	type:          "trigger" | "evade" | "detect" (required)
//	expectedRules: []string  — solve when one of these rules fires
//	forbiddenRules:[]string  — submission rejected once any of these has EVER
//	               fired for the participant, until they explicitly reset the
//	               taint (App-H2 persistent dirty flag —
//	               internal/store.MarkDirty/DirtyRules/ResetDirty via
//	               scoring.Grader.MarkDirtyOnRuleFire/evaluateClean). This is
//	               NOT a recent-window check: no amount of waiting clears it.
//	expectedFlag:  string (required for "evade"; must match FALCO{...})
//	windowSeconds: int (default 10) — informational only as of App-H2 (kept
//	               for UI display / historical config); it no longer gates any
//	               solve decision for either evade or trigger challenges.
//	requireExfil:  bool — evade only; solve also requires the user to have
//	               exfiltrated the correct flag to the collector
//	               (POST /api/challenges/{cid}/exfil) before submitting.
//	detect:        Detect — required for "detect"; the capture pair + rule
//	               skeleton the participant's condition is graded against
//	               (see Detect and the detect-challenge design doc).
package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var flagRE = regexp.MustCompile(`^FALCO\{[^}]+\}$`)

// DefaultDetectRuleName is the fixed rule name the participant condition is
// wrapped into when detect.ruleName is unset. The grader greps fires of this
// rule name across the two captures.
const DefaultDetectRuleName = "participant_detect"

// Detect holds the metadata for a "detect" challenge: the participant authors
// only a Falco `condition:` string, which the grader wraps into a fixed rule
// (RuleName) and replays against two pre-recorded captures — the evasion
// capture (must fire) and the benign capture (must NOT fire).
//
// EvasionCapturePath / BenignCapturePath are the validated, cleaned RELATIVE
// paths (relative to the challenge dir) resolved once at load time by
// resolveCapture. They are the SINGLE SOURCE for both the local-exec runner and
// the k8s-Job runner: neither may re-derive a path from the raw yaml or rebuild
// it from segments — doing so would reintroduce the `..`/absolute/symlink escape
// that resolveCapture rejects. Runners join these against a trusted base dir
// (the challenge dir, or a read-only in-image capture root) only.
type Detect struct {
	// Raw yaml inputs. EvasionCapture / BenignCapture are participant-facing
	// only in the sense that the OPERATOR authors them; they are never
	// participant-controlled at grade time (only the condition is).
	EvasionCapture string   `yaml:"evasionCapture"`
	BenignCapture  string   `yaml:"benignCapture"`
	RuleName       string   `yaml:"ruleName"`
	AllowedMacros  []string `yaml:"allowedMacros"`

	// Resolved, validated relative capture paths (populated by resolveCapture at
	// load time; cleaned, guaranteed within the challenge dir). Not yaml fields.
	EvasionCapturePath string `yaml:"-"`
	BenignCapturePath  string `yaml:"-"`
}

type Challenge struct {
	ID             string   `yaml:"challengeId"`
	Type           string   `yaml:"type"`
	ExpectedRules  []string `yaml:"expectedRules"`
	ForbiddenRules []string `yaml:"forbiddenRules"`
	ExpectedFlag   string   `yaml:"expectedFlag"`
	WindowSeconds  int      `yaml:"windowSeconds"`
	RequireExfil   bool     `yaml:"requireExfil"`
	Detect         *Detect  `yaml:"detect"`
	// dir is the challenge's directory name (e.g. "03-stealth-read-detect"),
	// captured at load time. Detect capture paths are relative to <catalogRoot>/<dir>.
	// Not a yaml field.
	dir string `yaml:"-"`
}

// Dir returns the challenge's directory name relative to the catalog root
// (empty for challenges constructed in tests without Load). Detect runners join
// the resolved capture paths against <catalogRoot>/<Dir> — never against
// participant input.
func (c Challenge) Dir() string { return c.dir }

type Catalog map[string]Challenge

// IDs returns challenge IDs in sorted order (stable for /api/state).
func (c Catalog) IDs() []string {
	ids := make([]string, 0, len(c))
	for id := range c {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Load reads every <dir>/<NN>-<slug>/falco-rule.yaml and returns a populated
// catalog. Missing dir returns an empty catalog (matches Python behavior).
func Load(dir string) (Catalog, error) {
	out := make(Catalog)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read catalog dir %q: %w", dir, err)
	}

	// Sort entries to make load order deterministic (matches Python `sorted(...)`).
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "falco-rule.yaml")
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue
		}
		ch, err := parseFile(path, e.Name())
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		out[ch.ID] = ch
	}
	return out, nil
}

func parseFile(path, dirName string) (Challenge, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Challenge{}, err
	}
	var ch Challenge
	if err := yaml.Unmarshal(data, &ch); err != nil {
		return Challenge{}, err
	}
	if ch.ID == "" {
		ch.ID = dirName
	}
	ch.dir = dirName
	if ch.Type == "" {
		return Challenge{}, fmt.Errorf("challenge %q: type must be \"trigger\", \"evade\" or \"detect\"", ch.ID)
	}
	if ch.WindowSeconds <= 0 {
		ch.WindowSeconds = 10
	}
	switch ch.Type {
	case "evade":
		if ch.ExpectedFlag == "" {
			return Challenge{}, fmt.Errorf("evade challenge %q: expectedFlag must not be empty", ch.ID)
		}
		if !flagRE.MatchString(ch.ExpectedFlag) {
			return Challenge{}, fmt.Errorf("evade challenge %q: expectedFlag must match FALCO{...}", ch.ID)
		}
	case "trigger":
		if len(ch.ExpectedRules) == 0 {
			return Challenge{}, fmt.Errorf("trigger challenge %q: expectedRules must not be empty", ch.ID)
		}
	case "detect":
		if err := validateDetect(&ch); err != nil {
			return Challenge{}, err
		}
	default:
		return Challenge{}, fmt.Errorf("challenge %q: unknown type %q, must be \"trigger\", \"evade\" or \"detect\"", ch.ID, ch.Type)
	}
	return ch, nil
}

// validateDetect checks a detect challenge's Detect block and populates the
// resolved capture paths. Detect challenges are NOT flag-based (no expectedFlag)
// and NOT live-Falco-based (no expectedRules/forbiddenRules); those are left
// empty by design. It fails fast at boot on a bad catalog so a mis-authored
// capture path can never reach a runner.
func validateDetect(ch *Challenge) error {
	if ch.Detect == nil {
		return fmt.Errorf("detect challenge %q: detect block is required", ch.ID)
	}
	if ch.ExpectedFlag != "" {
		return fmt.Errorf("detect challenge %q: expectedFlag must be empty (detect is not flag-based)", ch.ID)
	}
	if len(ch.ExpectedRules) != 0 || len(ch.ForbiddenRules) != 0 {
		return fmt.Errorf("detect challenge %q: expectedRules/forbiddenRules must be empty (detect grades by capture replay, not live Falco)", ch.ID)
	}
	if ch.Detect.RuleName == "" {
		ch.Detect.RuleName = DefaultDetectRuleName
	}
	evasion, err := resolveCapture(ch.ID, "evasionCapture", ch.Detect.EvasionCapture)
	if err != nil {
		return err
	}
	benign, err := resolveCapture(ch.ID, "benignCapture", ch.Detect.BenignCapture)
	if err != nil {
		return err
	}
	ch.Detect.EvasionCapturePath = evasion
	ch.Detect.BenignCapturePath = benign
	return nil
}

// resolveCapture is the SINGLE source of capture-path validation for detect
// challenges. It rejects, at load time, any path that is empty, absolute, or
// escapes the challenge directory (`..` traversal or an absolute clean result),
// and returns a cleaned RELATIVE path (forward-slash, no leading `./`) that
// runners join against a trusted base dir.
//
// Why relative + cleaned once here: the resolved value is the ONLY path any
// runner (local-exec or k8s-Job) is allowed to use. Because it is already
// cleaned and proven in-bounds, a runner that does filepath.Join(base, path)
// cannot be tricked into reading outside base — there is no re-parse of the raw
// yaml and no reconstruction from user segments. Symlink escape is addressed by
// the runner joining under a base IT controls (the read-only in-image capture
// root / the challenge dir), never following a symlink out; the path itself
// carries no `..`, so a same-name symlink is the only residual and is an
// operator-provenance concern (captures are operator fixtures, §5), not a
// participant-controlled input.
func resolveCapture(cid, field, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("detect challenge %q: detect.%s must not be empty", cid, field)
	}
	if filepath.IsAbs(raw) || strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("detect challenge %q: detect.%s must be a relative path, got %q", cid, field, raw)
	}
	clean := filepath.Clean(raw)
	// After Clean, any escape shows up as a leading ".." segment or an absolute
	// path. Reject both — the path must stay within the challenge dir.
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("detect challenge %q: detect.%s escapes the challenge dir: %q", cid, field, raw)
	}
	if clean == "." {
		return "", fmt.Errorf("detect challenge %q: detect.%s resolves to the challenge dir itself", cid, field)
	}
	return filepath.ToSlash(clean), nil
}
