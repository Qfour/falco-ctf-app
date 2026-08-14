package detect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// detectCatalog is a minimal in-memory catalog with one detect challenge whose
// resolved capture paths are set directly (the resolveCapture validation is
// exercised in catalog_test). LocalExec only needs Type=="detect", a non-nil
// Detect with a RuleName and the two capture paths.
func detectCatalog(t *testing.T) catalog.Catalog {
	t.Helper()
	return catalog.Catalog{
		"04-detect": catalog.Challenge{
			ID:   "04-detect",
			Type: "detect",
			Detect: &catalog.Detect{
				RuleName:           "participant_detect",
				AllowedMacros:      []string{"open_read", "sensitive_files"},
				EvasionCapturePath: "detect/evasion.scap",
				BenignCapturePath:  "detect/benign.scap",
			},
		},
	}
}

// scriptedRunner returns a falcoRunner whose behaviour is chosen per invocation
// by inspecting args: the compile gate call carries "-V"; the two replays carry
// "-c" (a replay config path). The test scripts (stdout, exitCode, err) for the
// compile gate and for each replay so every branch of Grade is reachable
// deterministically without a real Falco.
type scriptedRunner struct {
	// compile gate result:
	compileCode int
	compileErr  error
	// replay results keyed by the capture rel-path substring in the -c cfg name;
	// the sanitized cfg name embeds the capture path (see localexec.replay), so we
	// match on "evasion" / "benign".
	evasionStdout string
	evasionCode   int
	evasionErr    error
	benignStdout  string
	benignCode    int
	benignErr     error

	compileCalls int
	replayCalls  int
}

func (s *scriptedRunner) run() falcoRunner {
	return func(_ context.Context, _, _ string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "-V") {
			s.compileCalls++
			return "", s.compileCode, s.compileErr
		}
		s.replayCalls++
		// The replay config file name embeds the sanitized capture path; the first
		// replay is the evasion capture, the second the benign (Grade order).
		if strings.Contains(joined, "evasion") {
			return s.evasionStdout, s.evasionCode, s.evasionErr
		}
		return s.benignStdout, s.benignCode, s.benignErr
	}
}

// fireLine is a JSON alert line countFires recognises for the given rule name.
func fireLine(rule string) string {
	return `{"rule":"` + rule + `","output":"x"}`
}

func newLocalExec(cat catalog.Catalog, r falcoRunner) *LocalExec {
	return &LocalExec{cat: cat, challengesDir: "/tmp/challenges", runFalco: r}
}

func TestLocalExec_Grade_CompileFail_Invalid(t *testing.T) {
	cat := detectCatalog(t)
	sr := &scriptedRunner{compileCode: 1} // falco -V non-zero → invalid
	l := newLocalExec(cat, sr.run())

	ef, bf, invalid, err := l.Grade(context.Background(), "04-detect", "bogus condition")
	if err != nil {
		t.Fatalf("compile failure must be invalid, not an infra error: %v", err)
	}
	if !invalid {
		t.Fatal("non-zero falco -V must map to invalid=true")
	}
	if ef != 0 || bf != 0 {
		t.Fatalf("invalid must return zero counts, got ef=%d bf=%d", ef, bf)
	}
	if sr.replayCalls != 0 {
		t.Fatalf("no replay may run when the compile gate fails; replays=%d", sr.replayCalls)
	}
}

func TestLocalExec_Grade_MissedEvasion(t *testing.T) {
	cat := detectCatalog(t)
	// compiles; fires 0× on both → evasionFires 0 (Grader maps to missed).
	sr := &scriptedRunner{}
	l := newLocalExec(cat, sr.run())

	ef, bf, invalid, err := l.Grade(context.Background(), "04-detect", "cond")
	if err != nil || invalid {
		t.Fatalf("clean compile must be valid, got invalid=%v err=%v", invalid, err)
	}
	if ef != 0 || bf != 0 {
		t.Fatalf("want 0/0 fires, got ef=%d bf=%d", ef, bf)
	}
	if sr.replayCalls != 2 {
		t.Fatalf("both replays must run after a clean compile; replays=%d", sr.replayCalls)
	}
}

func TestLocalExec_Grade_Solved(t *testing.T) {
	cat := detectCatalog(t)
	rule := "participant_detect"
	sr := &scriptedRunner{
		evasionStdout: fireLine(rule) + "\n" + fireLine(rule), // 2 fires on evasion
		benignStdout:  "some non-alert log line\n",            // 0 fires on benign
	}
	l := newLocalExec(cat, sr.run())

	ef, bf, invalid, err := l.Grade(context.Background(), "04-detect", "cond")
	if err != nil || invalid {
		t.Fatalf("valid solve grade, got invalid=%v err=%v", invalid, err)
	}
	if ef != 2 || bf != 0 {
		t.Fatalf("want ef=2 bf=0 (solve), got ef=%d bf=%d", ef, bf)
	}
}

func TestLocalExec_Grade_FalsePositive(t *testing.T) {
	cat := detectCatalog(t)
	rule := "participant_detect"
	sr := &scriptedRunner{
		evasionStdout: fireLine(rule),
		benignStdout:  fireLine(rule), // also fires on benign → false positive
	}
	l := newLocalExec(cat, sr.run())

	ef, bf, _, err := l.Grade(context.Background(), "04-detect", "cond")
	if err != nil {
		t.Fatal(err)
	}
	if ef != 1 || bf != 1 {
		t.Fatalf("want ef=1 bf=1 (false positive), got ef=%d bf=%d", ef, bf)
	}
}

// TestLocalExec_Grade_ReplayFailClosed is the C4 regression: the compile gate
// passed, but a replay exits NON-ZERO (e.g. a corrupt capture) while reporting 0
// fires. The OLD code discarded the exit code and would return that 0 as a
// verdict — a benign replay crashing with 0 fires then looks like "no false
// positive", so an evasion-firing condition would MIS-SOLVE. The fix surfaces a
// non-zero post-compile replay as an infra error so the Grader fails closed
// (500), never a solve.
func TestLocalExec_Grade_ReplayFailClosed_Benign(t *testing.T) {
	cat := detectCatalog(t)
	rule := "participant_detect"
	sr := &scriptedRunner{
		evasionStdout: fireLine(rule), // would-be solve on the evasion side
		// benign replay CRASHES: non-zero exit, 0 fires (looks clean but isn't).
		benignStdout: "",
		benignCode:   2,
	}
	l := newLocalExec(cat, sr.run())

	_, _, _, err := l.Grade(context.Background(), "04-detect", "cond")
	if err == nil {
		t.Fatal("a non-zero post-compile replay exit must be an infra error (fail-closed), not a clean 0-fire verdict")
	}
}

// The evasion replay crashing must equally fail closed (symmetry).
func TestLocalExec_Grade_ReplayFailClosed_Evasion(t *testing.T) {
	cat := detectCatalog(t)
	sr := &scriptedRunner{evasionCode: 3}
	l := newLocalExec(cat, sr.run())

	if _, _, _, err := l.Grade(context.Background(), "04-detect", "cond"); err == nil {
		t.Fatal("a non-zero evasion replay exit must fail closed")
	}
}

// A genuine infra error (docker could not start: err != nil) on the compile gate
// is surfaced as an error, not invalid.
func TestLocalExec_Grade_CompileInfraError(t *testing.T) {
	cat := detectCatalog(t)
	sr := &scriptedRunner{compileErr: errors.New("docker daemon down")}
	l := newLocalExec(cat, sr.run())

	if _, _, invalid, err := l.Grade(context.Background(), "04-detect", "cond"); err == nil || invalid {
		t.Fatalf("compile infra error must return err (not invalid), got invalid=%v err=%v", invalid, err)
	}
}

func TestLocalExec_Grade_OversizedConditionInvalid(t *testing.T) {
	cat := detectCatalog(t)
	sr := &scriptedRunner{}
	l := newLocalExec(cat, sr.run())
	big := strings.Repeat("a", MaxConditionBytes+1)

	_, _, invalid, err := l.Grade(context.Background(), "04-detect", big)
	if err != nil || !invalid {
		t.Fatalf("oversized condition must be invalid without running, got invalid=%v err=%v", invalid, err)
	}
	if sr.compileCalls != 0 || sr.replayCalls != 0 {
		t.Fatal("oversized condition must never invoke falco")
	}
}

func TestLocalExec_Grade_NonDetectChallenge(t *testing.T) {
	cat := catalog.Catalog{"x": catalog.Challenge{ID: "x", Type: "trigger"}}
	sr := &scriptedRunner{}
	l := newLocalExec(cat, sr.run())
	if _, _, _, err := l.Grade(context.Background(), "x", "cond"); err == nil {
		t.Fatal("grading a non-detect challenge must error")
	}
	if _, _, _, err := l.Grade(context.Background(), "missing", "cond"); err == nil {
		t.Fatal("grading an unknown challenge must error")
	}
}

// --- buildRulesFile / countFires --------------------------------------------

func TestBuildRulesFile_EmbedsMacrosAndCondition(t *testing.T) {
	d := &catalog.Detect{
		RuleName:      "participant_detect",
		AllowedMacros: []string{"open_read", "sensitive_files"},
	}
	out, err := buildRulesFile(d, "open_read and sensitive_files")
	if err != nil {
		t.Fatal(err)
	}
	// Both allowed macros are emitted as macro blocks.
	if !strings.Contains(out, "- macro: open_read") || !strings.Contains(out, "- macro: sensitive_files") {
		t.Fatalf("allowed macros must be emitted:\n%s", out)
	}
	// The fixed rule wraps the participant condition (as an indented block scalar).
	if !strings.Contains(out, "- rule: participant_detect") {
		t.Fatalf("wrapped rule name missing:\n%s", out)
	}
	if !strings.Contains(out, "    open_read and sensitive_files") {
		t.Fatalf("participant condition must be embedded as an indented block:\n%s", out)
	}
}

func TestBuildRulesFile_UndefinedMacroFails(t *testing.T) {
	d := &catalog.Detect{RuleName: "r", AllowedMacros: []string{"no_such_macro"}}
	if _, err := buildRulesFile(d, "x"); err == nil {
		t.Fatal("an allowedMacros entry with no curated definition must fail fast")
	}
}

func TestBuildRulesFile_NilDetect(t *testing.T) {
	if _, err := buildRulesFile(nil, "x"); err == nil {
		t.Fatal("nil Detect must error")
	}
}

func TestCountFires(t *testing.T) {
	rule := "participant_detect"
	stdout := strings.Join([]string{
		fireLine(rule),
		`{"rule": "participant_detect","output":"spaced colon"}`, // tolerate space after colon
		`{"rule":"some_other_rule"}`,                              // different rule, not counted
		"plain log line, not json",
	}, "\n")
	if n := countFires(stdout, rule); n != 2 {
		t.Fatalf("want 2 fires of %q, got %d", rule, n)
	}
	if n := countFires("", rule); n != 0 {
		t.Fatalf("empty stdout must be 0 fires, got %d", n)
	}
}
