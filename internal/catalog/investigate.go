package catalog

// investigate.go is the catalog side of the 4th challenge type (ADR-0056 D1,
// Proposed): a question-and-answer challenge whose answers are facts a
// participant derives from an evidence bundle. The catalog holds only the SHAPE
// of the questions (id, format, attempts, params); an answer is never here
// (ADR-0056 D1: "答えは catalog にも journey にも置かない").
//
//	type: investigate
//	investigate:                  # decoded strictly: an unknown key fails the load
//	  evidence:
//	    mountDir: /abs/dir        # where the bundle is mounted; declared as a plant-target (A5)
//	  questions:                  # 1..8, ordered
//	    - id: <qid>               # answerformat.IDPattern, unique in the challenge
//	      format: <answerformat>  # the closed list (answerformat.Formats)
//	      attempts: <1..10>       # default 5
//	      params: {...}           # the keys of that format only
//
// Scope of this file (stage A1): the type, its strict decode, and the load-time
// checks of ADR-0056 D1, D3 (a) and V10. Grading, the route, the store and the
// edition (answers table, bundle) are later stages and are NOT reachable from
// here: until A3 the scoreboard refuses to score an investigate challenge
// (Catalog.refuseUngraded).

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// TypeInvestigate is the `type:` value of the 4th challenge type. The name is
// provisional (ADR-0056 D1: the CPO decides). It is spelled here and nowhere
// else in Go, so a rename is this one constant (and the yaml that uses it).
const TypeInvestigate = "investigate"

const (
	// MaxQuestions is the largest number of questions one challenge may ask (D1).
	MaxQuestions = 8
	// DefaultAttempts is the attempts of a question that does not write `attempts` (D1).
	DefaultAttempts = 5
)

// Investigate is the `investigate:` block.
type Investigate struct {
	Evidence  Evidence   `yaml:"evidence"`
	Questions []Question `yaml:"questions"`
}

// Evidence declares where the evidence bundle is mounted in the challenge container.
type Evidence struct {
	MountDir string `yaml:"mountDir"`
}

// Question is the shape of one question. The prompt is in journey.yaml
// (JourneyQuestion), never here.
type Question struct {
	ID     string              `yaml:"id"`
	Format string              `yaml:"format"`
	Params answerformat.Params `yaml:"params"`
	// AttemptsDeclared is `attempts:` as written (nil = not written). It is only
	// the decode target: read Attempts, which is DefaultAttempts or the validated value.
	AttemptsDeclared *int `yaml:"attempts"`
	// Attempts is the validated attempt budget of (user, challenge, question) (D7).
	Attempts int `yaml:"-"`
}

// UnmarshalYAML decodes the block with KnownFields(true) at every depth: an
// unknown key is an error. An investigate challenge's falco-rule.yaml top level
// is strict as well (parseFile, decodeStrictBytes); trigger / evade / detect
// keep decoding as before.
func (i *Investigate) UnmarshalYAML(node *yaml.Node) error {
	type plain Investigate // no methods: decoding into it does not recurse here
	if err := decodeStrict(node, (*plain)(i)); err != nil {
		return fmt.Errorf("investigate block: %w", err)
	}
	return nil
}

// decodeStrict decodes node into out, refusing keys out already knows nothing
// about. yaml.v3 only offers KnownFields on a Decoder, so the node is
// re-encoded and read back; line numbers in its errors are relative to that node.
func decodeStrict(node *yaml.Node, out any) error {
	b, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(out)
}

// decodeStrictBytes decodes a whole yaml document into out, refusing keys out
// knows nothing about. It is the top-level counterpart of decodeStrict: an
// investigate challenge's falco-rule.yaml and journey.yaml are read through it
// (ADR-0056 D1, V25), and no other type's file is.
func decodeStrictBytes(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

// ruleFileKeys is the schema an investigate challenge's falco-rule.yaml is held to
// when it is decoded strictly (ADR-0056 D1, V25): every top-level key that ANY
// consumer of the file reads. The Go catalog reads Challenge's keys; the other
// consumers are shell / python that match single lines (check-challenge-rules.sh,
// validate-flags-file.sh, the image builder: all keys Challenge already has) and
// scripts/gen-attack-layer.py, which requires the top-level `attack:` block of
// every challenge (make gen-attack, a CI check). A strict schema that left `attack`
// out would make an investigate challenge impossible to write: it could not satisfy
// the catalog and gen-attack at once. TestStrictSchemas_CoverEveryRealFile decodes
// every real falco-rule.yaml through this type, so a key a consumer needs and this
// type lacks is red.
type ruleFileKeys struct {
	Challenge `yaml:",inline"`
	Attack    *attackBlock `yaml:"attack"`
}

// attackBlock is the `attack:` block gen-attack-layer.py reads (all three keys
// required by it). Decoded strictly like everything else of an investigate
// challenge: an unknown key inside it is a load failure.
type attackBlock struct {
	Tactic        string `yaml:"tactic"`
	TechniqueID   string `yaml:"techniqueId"`
	TechniqueName string `yaml:"techniqueName"`
}

// reservedMountRoots are directories no evidence bundle may be mounted over or
// above. They mirror challenges/gen-values.sh (SEED_ROOT, SNAPSHOT_ROOT) and the
// I16 missions path; A5 (gen-values) is where a drift between the two is caught.
var reservedMountRoots = []string{
	// fixtures (I16)
	"/opt/ctf/missions",
	// seed root (gen-values.sh SEED_ROOT)
	"/plant-seed",
	// build-time snapshot root (gen-values.sh SNAPSHOT_ROOT)
	"/opt/ctf/plant-seed",
}

var mountElemRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validateMountDir is the part of ADR-0056 D1's `mountDir` rule that Go can
// check on its own: an absolute, already-clean path of plain elements that does
// not overlap the missions fixtures, the seed root or its snapshot.
//
// NOT checked here (stage A5, challenges/gen-values.sh): that mountDir is
// outside sensitive_dir_prefixes (gen-values.sh derives that list from the
// sensitive_files macro; copying it into Go would make a second list that
// drifts), and that it shares no file with another plant-target (ADR-0055 C4 (ii)).
func validateMountDir(dir string) error {
	if dir == "" {
		return errors.New("evidence.mountDir must not be empty")
	}
	if !strings.HasPrefix(dir, "/") || dir == "/" || path.Clean(dir) != dir {
		return fmt.Errorf("evidence.mountDir must be an absolute, clean path other than / (no trailing or doubled slash, no . or .. element), got %q", dir)
	}
	for _, elem := range strings.Split(dir[1:], "/") {
		if !mountElemRE.MatchString(elem) {
			return fmt.Errorf("evidence.mountDir element %q is outside [A-Za-z0-9._-]", elem)
		}
	}
	for _, root := range reservedMountRoots {
		if dir == root || strings.HasPrefix(dir, root+"/") || strings.HasPrefix(root, dir+"/") {
			return fmt.Errorf("evidence.mountDir %q overlaps %s", dir, root)
		}
	}
	return nil
}

// validateInvestigate checks an investigate challenge and fills each question's
// Attempts. Like detect, an investigate challenge is not flag-based and not
// live-Falco-based, so every key of those is required to be empty.
func validateInvestigate(ch *Challenge) error {
	inv := ch.Investigate
	if inv == nil {
		return fmt.Errorf("%s challenge %q: investigate block is required", TypeInvestigate, ch.ID)
	}
	if ch.ExpectedFlag != "" {
		return fmt.Errorf("%s challenge %q: expectedFlag must be empty (not flag-based)", TypeInvestigate, ch.ID)
	}
	if len(ch.ExpectedRules) != 0 || len(ch.ForbiddenRules) != 0 {
		return fmt.Errorf("%s challenge %q: expectedRules/forbiddenRules must be empty (not graded by live Falco)", TypeInvestigate, ch.ID)
	}
	if ch.RequireExfil || ch.RequireExpectedRuleFire {
		return fmt.Errorf("%s challenge %q: requireExfil/requireExpectedRuleFire must be false (evade only)", TypeInvestigate, ch.ID)
	}
	if ch.Detect != nil {
		return fmt.Errorf("%s challenge %q: detect block must be absent", TypeInvestigate, ch.ID)
	}
	if err := validateMountDir(inv.Evidence.MountDir); err != nil {
		return fmt.Errorf("%s challenge %q: %w", TypeInvestigate, ch.ID, err)
	}
	if n := len(inv.Questions); n < 1 || n > MaxQuestions {
		return fmt.Errorf("%s challenge %q: questions needs 1..%d entries, got %d", TypeInvestigate, ch.ID, MaxQuestions, n)
	}
	seen := make(map[string]struct{}, len(inv.Questions))
	for i := range inv.Questions {
		q := &inv.Questions[i]
		if !answerformat.ValidID(q.ID) {
			return fmt.Errorf("%s challenge %q: questions[%d].id is outside %s", TypeInvestigate, ch.ID, i, answerformat.IDPattern)
		}
		if _, dup := seen[q.ID]; dup {
			return fmt.Errorf("%s challenge %q: duplicate question id %q", TypeInvestigate, ch.ID, q.ID)
		}
		seen[q.ID] = struct{}{}
		if err := validateQuestion(q); err != nil {
			return fmt.Errorf("%s challenge %q: question %q: %w", TypeInvestigate, ch.ID, q.ID, err)
		}
	}
	return requirePerSeatQuestion(ch)
}

func validateQuestion(q *Question) error {
	if !answerformat.Known(q.Format) {
		return fmt.Errorf("format %q is not one of %s", q.Format, strings.Join(answerformat.Formats(), ", "))
	}
	q.Attempts = DefaultAttempts
	if q.AttemptsDeclared != nil {
		q.Attempts = *q.AttemptsDeclared
	}
	if q.Attempts < 1 || q.Attempts > answerformat.MaxAttempts {
		return fmt.Errorf("attempts must be in 1..%d, got %d", answerformat.MaxAttempts, q.Attempts)
	}
	if err := answerformat.ValidateParams(q.Format, q.Params); err != nil {
		return err
	}
	// D3 (a): a space that cannot be computed (technique) is refused. A
	// vocabulary-sized space (path, name) is NOT sized here: the vocabulary is in
	// the edition, so CheckSpace says so with ErrSpaceFromVocabulary and the
	// catalog passes it on purpose. The edition validator (A4, B8) applies the same
	// rule to the renderer's vocabulary through answerformat.CheckSpaceN.
	err := answerformat.CheckSpace(q.Format, q.Params, q.Attempts)
	if errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
		return nil
	}
	return err
}

// requirePerSeatQuestion is ADR-0056 D1's rule that each investigate challenge
// has at least one question whose format can vary per seat (answerformat.PerSeat):
// solving needs every question right, so a challenge of fixed-answer questions
// only could be solved by sharing the answers on the Board. It is decided by the
// formats alone, so the catalog can check it without an edition. Whether that
// question carries the learning point (D1 (i)(ii)) is for review, not for code.
func requirePerSeatQuestion(ch *Challenge) error {
	var perSeat []string
	for _, f := range answerformat.Formats() {
		if answerformat.PerSeat(f) {
			perSeat = append(perSeat, f)
		}
	}
	for _, q := range ch.Investigate.Questions {
		if answerformat.PerSeat(q.Format) {
			return nil
		}
	}
	return fmt.Errorf("%s challenge %q: at least one question must use a format that can vary per seat (%s)", TypeInvestigate, ch.ID, strings.Join(perSeat, ", "))
}

// refuseUngraded is the one place that keeps an investigate challenge out of a
// running scoreboard until stage A3 gives it a grader: today every scoring path
// is gated by type and treats an unknown type as "not mine", so such a mission
// would be listed, could never be solved, and would say nothing about it. LoadScored
// (the only way cmd/scoreboard obtains its catalog) calls it; A3 removes it.
func (c Catalog) refuseUngraded() error {
	for _, id := range c.IDs() {
		if c[id].Type == TypeInvestigate {
			return fmt.Errorf("challenge %q is type %q, which this build does not grade yet (ADR-0056 stage A3): remove it from the scope", id, TypeInvestigate)
		}
	}
	return nil
}
