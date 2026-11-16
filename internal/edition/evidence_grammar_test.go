package edition_test

// ADR-0056 V52 (A4b, review R4#2): the grammars of a challenge id and of a bundle's file
// name are written once in Go (challengeid.Pattern and edition.NamePattern) and copied
// into two other places that cannot import Go:
//
//   - charts/ctf-user/templates/_helpers.tpl, ctf-user.evidence.check: three
//     `regexMatch "<literal>" $subject` lines. $m.challenge and $cid take a challenge id
//     (plant.mounts[].challenge and the keys of evidence.challenges); $name takes a file
//     name (evidence.challenges.<cid>.names[]);
//   - challenges/gen-values.sh: EVIDENCE_NAME_RE (a file name), and CHALLENGE_ID_RE (a
//     challenge id) that it applies to the same copy-source path.
//
// A copy that drifts would let the chart or the generator accept a name the validator
// refuses (or the other way round) and nothing would say so until a deploy. This test
// reads the copies as text and holds each to the Go definition. The lines it reads are
// named exactly (the template's by the subject it applies the literal to, the script's by
// the variable name, at the top level), not found by a loose search of the whole file; an
// extraction that finds nothing, or finds a line twice, is a failure, never "no
// difference". It is the style of internal/catalog's mountroots_parity_test.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

var (
	chartHelpersPath    = filepath.Join("..", "..", "charts", "ctf-user", "templates", "_helpers.tpl")
	genValuesScriptPath = filepath.Join("..", "..", "challenges", "gen-values.sh")
)

// helperRegexRE is one `{{- if not (regexMatch "<literal>" $subject) -}}` line of the
// template, whole line, for the three subjects the test knows. The literal is a Go
// template string: it is unquoted, not read raw.
var helperRegexRE = regexp.MustCompile(`(?m)^\{\{- if not \(regexMatch ("(?:[^"\\]|\\.)*") \$(m\.challenge|cid|name)\) -\}\}$`)

// The two grammars, by the name a copy is listed under.
const (
	kindChallengeID = "challenge id"
	kindFileName    = "file name"
)

// goGrammars are the Go definitions the copies are held to.
type goGrammars struct {
	challengeID string
	fileName    string
}

func (g goGrammars) of(kind string) string {
	if kind == kindFileName {
		return g.fileName
	}
	return g.challengeID
}

var realGrammars = goGrammars{challengeID: challengeid.Pattern, fileName: edition.NamePattern}

// templateCopies are the three literals of _helpers.tpl, by the subject they are applied to.
var templateCopies = []struct {
	subject string
	kind    string
}{
	{"m.challenge", kindChallengeID},
	{"cid", kindChallengeID},
	{"name", kindFileName},
}

// scriptCopies are the two assignments of gen-values.sh, by variable.
var scriptCopies = []struct {
	name string
	kind string
}{
	{"EVIDENCE_NAME_RE", kindFileName},
	{"CHALLENGE_ID_RE", kindChallengeID},
}

// evidenceGrammarError is the whole rule: every copy is present exactly once and equals
// the Go definition of its grammar. It returns the first difference.
func evidenceGrammarError(helpers, genValues string, g goGrammars) error {
	got := map[string][]string{}
	for _, m := range helperRegexRE.FindAllStringSubmatch(helpers, -1) {
		lit, err := strconv.Unquote(m[1])
		if err != nil {
			return fmt.Errorf("_helpers.tpl: the literal %s applied to $%s is not a Go string: %v", m[1], m[2], err)
		}
		got[m[2]] = append(got[m[2]], lit)
	}
	for _, c := range templateCopies {
		switch lits := got[c.subject]; {
		case len(lits) == 0:
			return fmt.Errorf("_helpers.tpl: no `regexMatch \"...\" $%s` line was found: the extraction is broken or the template moved", c.subject)
		case len(lits) > 1:
			return fmt.Errorf("_helpers.tpl: %d `regexMatch \"...\" $%s` lines were found, want exactly 1", len(lits), c.subject)
		case lits[0] != g.of(c.kind):
			return fmt.Errorf("_helpers.tpl applies %q to $%s, the Go definition of the %s is %q", lits[0], c.subject, c.kind, g.of(c.kind))
		}
	}
	for _, c := range scriptCopies {
		re := regexp.MustCompile(`(?m)^` + c.name + `=(?:'([^']*)'|"([^"]*)")[ \t]*(?:#.*)?$`)
		ms := re.FindAllStringSubmatch(genValues, -1)
		switch len(ms) {
		case 0:
			return fmt.Errorf("gen-values.sh: no top-level %s='...' assignment was found: the extraction is broken or the script moved", c.name)
		case 1:
		default:
			return fmt.Errorf("gen-values.sh: %s is assigned %d times: which one is the value is ambiguous", c.name, len(ms))
		}
		lit := ms[0][1]
		if lit == "" {
			lit = ms[0][2]
		}
		if lit != g.of(c.kind) {
			return fmt.Errorf("gen-values.sh: %s = %q, the Go definition of the %s is %q", c.name, lit, c.kind, g.of(c.kind))
		}
	}
	return nil
}

func readGrammarCopies(t *testing.T) (helpers, genValues string) {
	t.Helper()
	h, err := os.ReadFile(chartHelpersPath)
	if err != nil {
		t.Fatal(err)
	}
	g, err := os.ReadFile(genValuesScriptPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(h), string(g)
}

func TestEvidenceGrammar_ChartAndGenValuesMatchGo(t *testing.T) {
	helpers, genValues := readGrammarCopies(t)
	if err := evidenceGrammarError(helpers, genValues, realGrammars); err != nil {
		t.Error(err)
	}
}

// The check itself must be able to fail: a copy of each file with ONE literal changed is
// red, whichever literal it is; a line that moved out of the form the test reads is red
// (not "equal"); a second line is red; an empty extraction is red; and so is a Go
// definition that changed while the copies did not.
func TestEvidenceGrammar_CheckFailsOnADriftedCopy(t *testing.T) {
	helpers, genValues := readGrammarCopies(t)
	if err := evidenceGrammarError(helpers, genValues, realGrammars); err != nil {
		t.Fatalf("the real files are not equal to the Go definitions, so the negative cases below prove nothing: %v", err)
	}
	// unanchored is one mistake: the literal without its `^`.
	unanchored := func(p string) string { return strings.TrimPrefix(p, "^") }
	replaceOnce := func(t *testing.T, src, old, repl string) string {
		t.Helper()
		if n := strings.Count(src, old); n != 1 {
			t.Fatalf("the negative case's text %q must occur exactly once (%d times): rewording the line makes this check vacuous, update it", old, n)
		}
		return strings.Replace(src, old, repl, 1)
	}

	for _, c := range templateCopies {
		want := realGrammars.of(c.kind)
		line := `regexMatch "` + want + `" $` + c.subject
		drifted := replaceOnce(t, helpers, line, `regexMatch "`+unanchored(want)+`" $`+c.subject)
		if err := evidenceGrammarError(drifted, genValues, realGrammars); err == nil {
			t.Errorf("_helpers.tpl: changing only the literal applied to $%s was not detected", c.subject)
		}
		// a line that is no longer the whole line (indented) reads as missing, not as equal
		moved := replaceOnce(t, helpers, "{{- if not ("+line+")", "  {{- if not ("+line+")")
		if err := evidenceGrammarError(moved, genValues, realGrammars); err == nil {
			t.Errorf("_helpers.tpl: the $%s line moved out of the form the test reads was accepted", c.subject)
		}
		twice := helpers + "\n{{- if not (" + line + ") -}}\n"
		if err := evidenceGrammarError(twice, genValues, realGrammars); err == nil {
			t.Errorf("_helpers.tpl: a second $%s line was accepted", c.subject)
		}
	}
	for _, c := range scriptCopies {
		want := realGrammars.of(c.kind)
		line := c.name + "='" + want + "'"
		drifted := replaceOnce(t, genValues, line, c.name+"='"+unanchored(want)+"'")
		if err := evidenceGrammarError(helpers, drifted, realGrammars); err == nil {
			t.Errorf("gen-values.sh: changing only %s was not detected", c.name)
		}
		// the same value in double quotes still reads: the rule is the value, not the quoting
		dq := replaceOnce(t, genValues, line, c.name+`="`+want+`"`)
		if err := evidenceGrammarError(helpers, dq, realGrammars); err != nil {
			t.Errorf("gen-values.sh: %s in double quotes: %v", c.name, err)
		}
		moved := replaceOnce(t, genValues, line, "  "+line)
		if err := evidenceGrammarError(helpers, moved, realGrammars); err == nil {
			t.Errorf("gen-values.sh: %s no longer at the top level was accepted", c.name)
		}
		if err := evidenceGrammarError(helpers, genValues+"\n"+c.name+"='other'\n", realGrammars); err == nil {
			t.Errorf("gen-values.sh: a second %s assignment was accepted", c.name)
		}
	}

	// the Go side drifting is red too: the real copies against a changed definition
	for name, g := range map[string]goGrammars{
		"a changed challenge-id grammar": {challengeID: challengeid.Pattern + "x", fileName: edition.NamePattern},
		"a changed file-name grammar":    {challengeID: challengeid.Pattern, fileName: edition.NamePattern + "x"},
	} {
		if err := evidenceGrammarError(helpers, genValues, g); err == nil {
			t.Errorf("%s: the copies were accepted", name)
		}
	}
	// an empty extraction is red
	if err := evidenceGrammarError("", genValues, realGrammars); err == nil {
		t.Error("an empty template was accepted")
	}
	if err := evidenceGrammarError(helpers, "echo EVIDENCE_NAME_RE CHALLENGE_ID_RE\n", realGrammars); err == nil {
		t.Error("a script with no assignment was accepted")
	}
}
