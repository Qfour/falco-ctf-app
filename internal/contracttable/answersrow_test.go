package contracttable

// ADR-0056 V33 (A4-0): the contract table's "答え表" row is read by platform (its
// helmfile enables `answersSecret` and names the Secret and its key from this row),
// so the literals the row quotes must be the ones the chart really has:
//
//	(a) the row exists in the conventions file;
//	(b) every code span it quotes (the Secret's default name and key, the mount path,
//	    the ANSWERS_FILE form, the key's regular expression, the `enabled` default)
//	    equals what charts/scoreboard/values.yaml and templates/deployment.yaml say;
//	(c) changing ONE side only (the row, the values or the template, as a copy of
//	    the real text) turns (b) red.
//
// The chart's two files are read as text, by the one line pattern each, and a
// pattern that finds nothing is an error (never a skip): the files are in the Docker
// test context (.dockerignore keeps charts/scoreboard).

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const (
	answersValuesPath     = "charts/scoreboard/values.yaml"
	answersDeploymentPath = "charts/scoreboard/templates/deployment.yaml"
	answersRowPrefix      = "| 答え表 (ADR-0056"
)

var (
	// the container's mount: `- name: answers` followed by its mountPath and
	// `readOnly: true` (the volume entry of the same name has `secret:` instead).
	answersMountRe = regexp.MustCompile(`- name: answers\n\s*mountPath: (\S+)\n\s*readOnly: true\n`)
	// the env entry that names the file.
	answersEnvRe = regexp.MustCompile(`- name: ANSWERS_FILE\n\s*value: (.+)\n`)
	// the render-time refusal of a key that is not a file name.
	answersKeyRe = regexp.MustCompile(`regexMatch "([^"]+)" \(toString \.Values\.answersSecret\.key\)`)
)

// answersRow returns the row of the conventions text, or an error when there is none.
func answersRow(conventions string) (string, error) {
	row := RowWhere(conventions, func(r string) bool { return strings.HasPrefix(r, answersRowPrefix) })
	if row == "" {
		return "", fmt.Errorf("the contract table has no `%s` row (ADR-0056 D16, A4-0)", answersRowPrefix)
	}
	return row, nil
}

// answersSecretDefaults reads the `enabled` / `name` / `key` lines of the
// `answersSecret:` block of values.yaml (the block ends at the first line that is not
// indented, a comment or blank). All three must be there.
func answersSecretDefaults(values string) (map[string]string, error) {
	lines := strings.Split(values, "\n")
	start := -1
	for i, ln := range lines {
		if ln == "answersSecret:" {
			if start >= 0 {
				return nil, fmt.Errorf("values.yaml has two `answersSecret:` blocks")
			}
			start = i
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("values.yaml has no `answersSecret:` block")
	}
	got := map[string]string{}
	for _, ln := range lines[start+1:] {
		if !strings.HasPrefix(ln, "  ") {
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			break
		}
		k, v, ok := strings.Cut(strings.TrimSpace(ln), ": ")
		if !ok {
			continue
		}
		got[k] = v
	}
	for _, k := range []string{"enabled", "name", "key"} {
		if got[k] == "" {
			return nil, fmt.Errorf("the `answersSecret:` block of values.yaml has no `%s`", k)
		}
	}
	return got, nil
}

// answersContractMismatch is nil when the row's literals are the chart's. It is the
// whole judgement of V33, on three texts.
func answersContractMismatch(conventions, values, deployment string) error {
	row, err := answersRow(conventions)
	if err != nil {
		return err
	}
	def, err := answersSecretDefaults(values)
	if err != nil {
		return err
	}
	m := answersMountRe.FindStringSubmatch(deployment)
	if m == nil {
		return fmt.Errorf("deployment.yaml has no readOnly `answers` mount")
	}
	mount := m[1]
	e := answersEnvRe.FindStringSubmatch(deployment)
	if e == nil {
		return fmt.Errorf("deployment.yaml has no ANSWERS_FILE env")
	}
	if want := mount + "/{{ .Values.answersSecret.key }}"; strings.TrimSpace(e[1]) != want {
		return fmt.Errorf("ANSWERS_FILE is %q in deployment.yaml, want %q (the mount path and the key)", e[1], want)
	}
	k := answersKeyRe.FindStringSubmatch(deployment)
	if k == nil {
		return fmt.Errorf("deployment.yaml has no regexMatch on answersSecret.key")
	}
	for _, c := range []struct{ what, lit string }{
		{"the `enabled` default", "`enabled` は既定 `" + def["enabled"] + "`"},
		{"the Secret's default name", "`name` は既定 `" + def["name"] + "`"},
		{"the key's default", "`key` は既定 `" + def["key"] + "`"},
		{"the mount path", "`" + mount + "`"},
		{"the ANSWERS_FILE form", "`ANSWERS_FILE=" + mount + "/<key>`"},
		{"the key's regular expression", "`" + k[1] + "`"},
	} {
		if !strings.Contains(row, c.lit) {
			return fmt.Errorf("the row does not quote %s as the chart has it: want %s in it", c.what, c.lit)
		}
	}
	if def["enabled"] != "false" {
		return fmt.Errorf("answersSecret.enabled defaults to %q: the table is off unless an event turns it on", def["enabled"])
	}
	return nil
}

// (a) + (b)
func TestAnswersRow_MatchesTheChart(t *testing.T) {
	err := answersContractMismatch(
		readRepoFile(t, Path),
		readRepoFile(t, answersValuesPath),
		readRepoFile(t, answersDeploymentPath),
	)
	if err != nil {
		t.Fatal(err)
	}
}

// The literals the ADR names are in the real row (a comparison that read both sides
// from one place could not notice the row losing them).
func TestAnswersRow_KeepsTheNamedLiterals(t *testing.T) {
	row, err := answersRow(readRepoFile(t, Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, lit := range []string{
		"`scoreboard-answers`", "`answers.tsv`", "`/etc/ctf-answers`", "`answersSecret`",
		"`ANSWERS_FILE=/etc/ctf-answers/<key>`", "`edition check failed`", "`edition loaded`",
		"# falco-ctf answers v1 run=<32 桁の小文字 hex>",
	} {
		if !strings.Contains(row, lit) {
			t.Errorf("the answers row no longer has %q", lit)
		}
	}
}

// (c) One side changed, the others real: each is red. A missing row, or a pattern
// that finds nothing, is red too.
func TestAnswersRow_OneSidedChangeIsRed(t *testing.T) {
	conv := readRepoFile(t, Path)
	vals := readRepoFile(t, answersValuesPath)
	dep := readRepoFile(t, answersDeploymentPath)
	if err := answersContractMismatch(conv, vals, dep); err != nil {
		t.Fatalf("the real texts already disagree: %v", err)
	}
	type side int
	const (
		inConv side = iota
		inVals
		inDep
	)
	for _, c := range []struct {
		name     string
		in       side
		old, new string
	}{
		{"row: the Secret's default name changed", inConv, "`name` は既定 `scoreboard-answers`", "`name` は既定 `scoreboard-answerz`"},
		{"row: the key's default changed", inConv, "`key` は既定 `answers.tsv`", "`key` は既定 `answer.tsv`"},
		{"row: the enabled default changed", inConv, "`enabled` は既定 `false`", "`enabled` は既定 `true`"},
		{"row: the mount path changed", inConv, "`/etc/ctf-answers` へ", "`/etc/ctf-answer` へ"},
		{"row: the ANSWERS_FILE form changed", inConv, "`ANSWERS_FILE=/etc/ctf-answers/<key>`", "`ANSWERS_FILE=/etc/ctf-answer/<key>`"},
		{"row: the key's regular expression changed", inConv, "`^[A-Za-z0-9][A-Za-z0-9._-]*$`", "`^[A-Za-z0-9][A-Za-z0-9._]*$`"},
		{"row: removed", inConv, answersRowPrefix, "| 答え表の行ではない (ADR-0056"},
		{"values: the Secret's default name changed", inVals, "  name: scoreboard-answers", "  name: scoreboard-answerz"},
		{"values: the key's default changed", inVals, "  key: answers.tsv", "  key: answers.csv"},
		{"values: enabled by default", inVals, "answersSecret:\n  enabled: false", "answersSecret:\n  enabled: true"},
		{"values: the block renamed", inVals, "answersSecret:\n", "answersSecretX:\n"},
		{"template: the mount path changed", inDep, "mountPath: /etc/ctf-answers\n", "mountPath: /etc/ctf-answer\n"},
		{"template: the mount not readOnly", inDep, "mountPath: /etc/ctf-answers\n              readOnly: true", "mountPath: /etc/ctf-answers\n              readOnly: false"},
		{"template: ANSWERS_FILE points elsewhere", inDep, "value: /etc/ctf-answers/{{ .Values.answersSecret.key }}", "value: /etc/ctf-answers/x"},
		{"template: the key's regular expression changed", inDep, `"^[A-Za-z0-9][A-Za-z0-9._-]*$" (toString .Values.answersSecret.key)`, `"^[A-Za-z0-9][A-Za-z0-9._]*$" (toString .Values.answersSecret.key)`},
	} {
		src := map[side]*string{inConv: &conv, inVals: &vals, inDep: &dep}[c.in]
		if !strings.Contains(*src, c.old) {
			t.Errorf("%s: the real text has no %q to change", c.name, c.old)
			continue
		}
		texts := [3]string{conv, vals, dep}
		texts[c.in] = strings.Replace(*src, c.old, c.new, 1)
		if err := answersContractMismatch(texts[0], texts[1], texts[2]); err == nil {
			t.Errorf("%s: answersContractMismatch accepted it", c.name)
		}
	}
	if err := answersContractMismatch("", vals, dep); err == nil {
		t.Error("an empty conventions text was accepted")
	}
	if err := answersContractMismatch(conv, "", dep); err == nil {
		t.Error("an empty values.yaml was accepted")
	}
	if err := answersContractMismatch(conv, vals, ""); err == nil {
		t.Error("an empty deployment.yaml was accepted")
	}
}
