package edition_test

// ADR-0056 V58 (A5c, review #633 R4#2), and the one literal V52 could not hold until
// deploy-user.sh had it: the limits of a bundle (files per bundle, bytes per bundle, bytes
// per seat) and the file-name grammar are written once in Go (edition.MaxBundleFiles,
// MaxBundleBytes, MaxSeatBytes, NamePattern) and copied into two places that cannot import
// Go:
//
//   - charts/ctf-user/templates/_helpers.tpl, ctf-user.evidence.check: the `64` of
//     `{{- if or (lt $n 1) (gt $n 64) -}}` (the chart refuses a `names` list longer than
//     that; it cannot see content, so it holds no byte limit);
//   - charts/ctf-user/deploy-user.sh: EVIDENCE_MAX_FILES, EVIDENCE_MAX_BUNDLE_BYTES,
//     EVIDENCE_MAX_SEAT_BYTES and EVIDENCE_NAME_PATTERN, each one top-level assignment
//     (it counts files and bytes before it touches a cluster, D11).
//
// A copy that drifts would let a deploy accept a bundle the validator refuses (or the other
// way round), and nothing would say so until a stand-up. This test reads the copies as text
// and holds each to the Go definition, in the style of evidence_grammar_test.go (V52): the
// line it reads is named exactly, a line that is missing or found twice is a failure (never
// "no difference"), and a copy with one literal changed must be red.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

var deployUserScriptPath = filepath.Join("..", "..", "charts", "ctf-user", "deploy-user.sh")

// helperMaxFilesRE is the template's names-count line, whole line.
var helperMaxFilesRE = regexp.MustCompile(`(?m)^\{\{- if or \(lt \$n 1\) \(gt \$n ([0-9]+)\) -\}\}$`)

// evidenceLimits are the Go definitions the copies are held to.
type evidenceLimits struct {
	files       int
	bundleBytes int
	seatBytes   int
	namePattern string
}

var realEvidenceLimits = evidenceLimits{
	files:       edition.MaxBundleFiles,
	bundleBytes: edition.MaxBundleBytes,
	seatBytes:   edition.MaxSeatBytes,
	namePattern: edition.NamePattern,
}

// shellLiteral is the value of the ONE top-level assignment NAME='...', NAME="..." or
// NAME=<bare word> of a script (an optional trailing comment is allowed). An assignment that
// is missing, indented (not top level), repeated or empty is an error.
func shellLiteral(script, name string) (string, error) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `=(?:'([^']*)'|"([^"]*)"|([^\s#'"]+))[ \t]*(?:#.*)?$`)
	ms := re.FindAllStringSubmatch(script, -1)
	switch len(ms) {
	case 0:
		return "", fmt.Errorf("deploy-user.sh: no top-level %s=... assignment was found: the extraction is broken or the script moved", name)
	case 1:
	default:
		return "", fmt.Errorf("deploy-user.sh: %s is assigned %d times: which one is the value is ambiguous", name, len(ms))
	}
	for _, g := range ms[0][1:] {
		if g != "" {
			return g, nil
		}
	}
	return "", fmt.Errorf("deploy-user.sh: %s is assigned an empty value", name)
}

func shellInt(script, name string) (int, error) {
	lit, err := shellLiteral(script, name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(lit)
	if err != nil {
		return 0, fmt.Errorf("deploy-user.sh: %s = %q is not a decimal integer", name, lit)
	}
	return n, nil
}

// evidenceLimitsError is the whole rule: every copy is present exactly once and equals the
// Go definition. It returns the first difference.
func evidenceLimitsError(deploy, helpers string, want evidenceLimits) error {
	ms := helperMaxFilesRE.FindAllStringSubmatch(helpers, -1)
	switch len(ms) {
	case 0:
		return fmt.Errorf("_helpers.tpl: no `{{- if or (lt $n 1) (gt $n <max>) -}}` line was found: the extraction is broken or the template moved")
	case 1:
	default:
		return fmt.Errorf("_helpers.tpl: %d `(gt $n <max>)` lines were found, want exactly 1", len(ms))
	}
	if n, err := strconv.Atoi(ms[0][1]); err != nil || n != want.files {
		return fmt.Errorf("_helpers.tpl refuses a names list over %s, the Go definition (MaxBundleFiles) is %d", ms[0][1], want.files)
	}
	for _, c := range []struct {
		name string
		want int
		what string
	}{
		{"EVIDENCE_MAX_FILES", want.files, "MaxBundleFiles"},
		{"EVIDENCE_MAX_BUNDLE_BYTES", want.bundleBytes, "MaxBundleBytes"},
		{"EVIDENCE_MAX_SEAT_BYTES", want.seatBytes, "MaxSeatBytes"},
	} {
		got, err := shellInt(deploy, c.name)
		if err != nil {
			return err
		}
		if got != c.want {
			return fmt.Errorf("deploy-user.sh: %s = %d, the Go definition (%s) is %d", c.name, got, c.what, c.want)
		}
	}
	pat, err := shellLiteral(deploy, "EVIDENCE_NAME_PATTERN")
	if err != nil {
		return err
	}
	if pat != want.namePattern {
		return fmt.Errorf("deploy-user.sh: EVIDENCE_NAME_PATTERN = %q, the Go definition (NamePattern) is %q", pat, want.namePattern)
	}
	return nil
}

func readLimitCopies(t *testing.T) (deploy, helpers string) {
	t.Helper()
	d, err := os.ReadFile(deployUserScriptPath)
	if err != nil {
		t.Fatal(err)
	}
	h, err := os.ReadFile(chartHelpersPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(d), string(h)
}

func TestEvidenceLimits_DeployUserAndChartMatchGo(t *testing.T) {
	deploy, helpers := readLimitCopies(t)
	if err := evidenceLimitsError(deploy, helpers, realEvidenceLimits); err != nil {
		t.Error(err)
	}
}

// The check itself must be able to fail: a copy with ONE literal changed is red, whichever
// literal it is; an assignment that moved out of the top level, a second assignment and an
// empty extraction are red; and so is a Go definition that changed while the copies did not.
func TestEvidenceLimits_CheckFailsOnADriftedCopy(t *testing.T) {
	deploy, helpers := readLimitCopies(t)
	if err := evidenceLimitsError(deploy, helpers, realEvidenceLimits); err != nil {
		t.Fatalf("the real files are not equal to the Go definitions, so the negative cases below prove nothing: %v", err)
	}
	replaceOnce := func(t *testing.T, src, old, repl string) string {
		t.Helper()
		if n := strings.Count(src, old); n != 1 {
			t.Fatalf("the negative case's text %q must occur exactly once (%d times): rewording the line makes this check vacuous, update it", old, n)
		}
		return strings.Replace(src, old, repl, 1)
	}

	for _, c := range []struct {
		name, lit, drifted string
	}{
		{"EVIDENCE_MAX_FILES", strconv.Itoa(edition.MaxBundleFiles), strconv.Itoa(edition.MaxBundleFiles + 1)},
		{"EVIDENCE_MAX_BUNDLE_BYTES", strconv.Itoa(edition.MaxBundleBytes), strconv.Itoa(edition.MaxBundleBytes + 1)},
		{"EVIDENCE_MAX_SEAT_BYTES", strconv.Itoa(edition.MaxSeatBytes), strconv.Itoa(edition.MaxSeatBytes - 1)},
		{"EVIDENCE_NAME_PATTERN", edition.NamePattern, strings.TrimPrefix(edition.NamePattern, "^")},
	} {
		line := c.name + "='" + c.lit + "'"
		drifted := replaceOnce(t, deploy, line, c.name+"='"+c.drifted+"'")
		if err := evidenceLimitsError(drifted, helpers, realEvidenceLimits); err == nil {
			t.Errorf("deploy-user.sh: changing only %s was not detected", c.name)
		}
		// the same value in double quotes still reads: the rule is the value, not the quoting
		dq := replaceOnce(t, deploy, line, c.name+`="`+c.lit+`"`)
		if err := evidenceLimitsError(dq, helpers, realEvidenceLimits); err != nil {
			t.Errorf("deploy-user.sh: %s in double quotes: %v", c.name, err)
		}
		moved := replaceOnce(t, deploy, line, "  "+line)
		if err := evidenceLimitsError(moved, helpers, realEvidenceLimits); err == nil {
			t.Errorf("deploy-user.sh: %s no longer at the top level was accepted", c.name)
		}
		if err := evidenceLimitsError(deploy+"\n"+c.name+"='1'\n", helpers, realEvidenceLimits); err == nil {
			t.Errorf("deploy-user.sh: a second %s assignment was accepted", c.name)
		}
	}

	// the template's literal
	tplLine := "(gt $n " + strconv.Itoa(edition.MaxBundleFiles) + ")"
	drifted := replaceOnce(t, helpers, tplLine, "(gt $n "+strconv.Itoa(edition.MaxBundleFiles+1)+")")
	if err := evidenceLimitsError(deploy, drifted, realEvidenceLimits); err == nil {
		t.Error("_helpers.tpl: changing only the names-count literal was not detected")
	}
	if err := evidenceLimitsError(deploy, replaceOnce(t, helpers, "{{- if or "+"(lt $n 1) "+tplLine, "  {{- if or (lt $n 1) "+tplLine), realEvidenceLimits); err == nil {
		t.Error("_helpers.tpl: the names-count line moved out of the form the test reads was accepted")
	}
	if err := evidenceLimitsError(deploy, helpers+"\n{{- if or (lt $n 1) "+tplLine+" -}}\n", realEvidenceLimits); err == nil {
		t.Error("_helpers.tpl: a second names-count line was accepted")
	}

	// the Go side drifting is red too: the real copies against a changed definition
	for name, g := range map[string]evidenceLimits{
		"a changed file count":   {edition.MaxBundleFiles + 1, edition.MaxBundleBytes, edition.MaxSeatBytes, edition.NamePattern},
		"a changed bundle limit": {edition.MaxBundleFiles, edition.MaxBundleBytes + 1, edition.MaxSeatBytes, edition.NamePattern},
		"a changed seat limit":   {edition.MaxBundleFiles, edition.MaxBundleBytes, edition.MaxSeatBytes + 1, edition.NamePattern},
		"a changed name grammar": {edition.MaxBundleFiles, edition.MaxBundleBytes, edition.MaxSeatBytes, edition.NamePattern + "x"},
	} {
		if err := evidenceLimitsError(deploy, helpers, g); err == nil {
			t.Errorf("%s: the copies were accepted", name)
		}
	}
	// an empty extraction is red
	if err := evidenceLimitsError("", helpers, realEvidenceLimits); err == nil {
		t.Error("an empty deploy-user.sh was accepted")
	}
	if err := evidenceLimitsError(deploy, "", realEvidenceLimits); err == nil {
		t.Error("an empty template was accepted")
	}
}

// The digests file's shape as deploy-user.sh reads it (A5c-1 review R4#2): its header prefix,
// the grammar of a run id, the all-zero practice run id and the grammar of a digest are
// copied from digests.go (digestsHeaderPrefix, validRunID, PracticeRunID, ValidDigest). The
// prefix is unexported, so it is read out of WriteDigests' own output (no export is added);
// the two grammars are held by behaviour, over probes, to the exported functions (a shell
// ERE and a Go RE2 agree on these simple forms); the practice id is the exported constant.

const (
	goldenRunID = "0123456789abcdef0123456789abcdef"
	hex64a      = "1111111111111111111111111111111111111111111111111111111111111111"
	hex64b      = "2222222222222222222222222222222222222222222222222222222222222222"
	hex64c      = "3333333333333333333333333333333333333333333333333333333333333333"
)

var goldenDigestsPath = filepath.Join("testdata", "digests-golden", "digests.tsv")

// goldenRows are the rows of the golden file, in an order that is not the file's.
func goldenRows() []edition.DigestRow {
	return []edition.DigestRow{
		{Seat: "user2", CID: "40-ev", Digest: hex64c},
		{Seat: "user1", CID: "41-ev", Digest: hex64b},
		{Seat: "user1", CID: "40-ev", Digest: hex64a},
	}
}

// WriteDigests' output for the golden rows is the golden file, byte for byte, and
// ParseDigests reads that file back to the same rows. scripts/check-deploy-user-evidence.sh
// runs deploy-user.sh over the same file (it must accept it).
func TestDigestsGolden_WriteDigestsOutputIsTheGoldenFile(t *testing.T) {
	want, err := os.ReadFile(goldenDigestsPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := edition.WriteDigests(&buf, goldenRunID, goldenRows()); err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(want) {
		t.Errorf("WriteDigests' output is not the golden file:\n got %q\nwant %q", buf.String(), string(want))
	}
	id, rows, err := edition.ParseDigests(want)
	if err != nil {
		t.Fatalf("ParseDigests refuses the golden file: %v", err)
	}
	if id != goldenRunID || len(rows) != 3 {
		t.Errorf("ParseDigests read run id %q and %d rows from the golden file", id, len(rows))
	}
}

// goWritesRunID reports whether WriteDigests takes runID.
func goWritesRunID(runID string) bool {
	var buf bytes.Buffer
	return edition.WriteDigests(&buf, runID, []edition.DigestRow{{Seat: "user1", CID: "40-ev", Digest: hex64a}}) == nil
}

// goHeaderPrefix is the header's text before the run id, as WriteDigests writes it.
func goHeaderPrefix(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := edition.WriteDigests(&buf, goldenRunID, goldenRows()); err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(buf.String(), "\n")
	prefix, ok := strings.CutSuffix(first, goldenRunID)
	if !ok || prefix == "" {
		t.Fatalf("the first line of WriteDigests' output is %q, want a prefix and the run id", first)
	}
	return prefix
}

// digestsShapeError is the whole rule for the four literals of deploy-user.sh.
func digestsShapeError(deploy, goPrefix string) error {
	prefix, err := shellLiteral(deploy, "EVIDENCE_DIGESTS_PREFIX")
	if err != nil {
		return err
	}
	if prefix != goPrefix {
		return fmt.Errorf("deploy-user.sh: EVIDENCE_DIGESTS_PREFIX = %q, WriteDigests' header prefix is %q", prefix, goPrefix)
	}
	practice, err := shellLiteral(deploy, "EVIDENCE_PRACTICE_RUN_ID")
	if err != nil {
		return err
	}
	if practice != edition.PracticeRunID {
		return fmt.Errorf("deploy-user.sh: EVIDENCE_PRACTICE_RUN_ID = %q, PracticeRunID is %q", practice, edition.PracticeRunID)
	}
	return digestsGrammarError(deploy, goPrefix, practice)
}

// digestsGrammarError holds EVIDENCE_DIGESTS_HEADER_RE and EVIDENCE_DIGEST_RE to Go's
// acceptance of a run id and of a digest, probe by probe. deploy-user.sh accepts a header
// when the ERE matches and the run id is not the practice id.
func digestsGrammarError(deploy, goPrefix, practice string) error {
	headerLit, err := shellLiteral(deploy, "EVIDENCE_DIGESTS_HEADER_RE")
	if err != nil {
		return err
	}
	headerRE, err := regexp.Compile(headerLit)
	if err != nil {
		return fmt.Errorf("deploy-user.sh: EVIDENCE_DIGESTS_HEADER_RE %q does not compile: %v", headerLit, err)
	}
	for _, id := range []string{
		goldenRunID, practice, strings.Repeat("f", 32), strings.Repeat("a", 31), strings.Repeat("a", 33),
		strings.ToUpper(goldenRunID), strings.Repeat("g", 32), "", goldenRunID + "\n", " " + goldenRunID,
	} {
		shellAccepts := headerRE.MatchString(goPrefix+id) && id != practice
		if goAccepts := goWritesRunID(id); shellAccepts != goAccepts {
			return fmt.Errorf("deploy-user.sh reads the header with run id %q as accepted=%v, WriteDigests takes it: %v", id, shellAccepts, goAccepts)
		}
	}
	digestLit, err := shellLiteral(deploy, "EVIDENCE_DIGEST_RE")
	if err != nil {
		return err
	}
	digestRE, err := regexp.Compile(digestLit)
	if err != nil {
		return fmt.Errorf("deploy-user.sh: EVIDENCE_DIGEST_RE %q does not compile: %v", digestLit, err)
	}
	for _, d := range []string{
		hex64a, strings.Repeat("a", 63), strings.Repeat("a", 65), strings.ToUpper(strings.Repeat("a", 64)),
		strings.Repeat("g", 64), "", hex64a + "\n",
	} {
		if got, want := digestRE.MatchString(d), edition.ValidDigest(d); got != want {
			return fmt.Errorf("deploy-user.sh: EVIDENCE_DIGEST_RE matches %q = %v, ValidDigest says %v", d, got, want)
		}
	}
	return nil
}

func TestEvidenceDigestsShape_DeployUserMatchesGo(t *testing.T) {
	deploy, _ := readLimitCopies(t)
	if err := digestsShapeError(deploy, goHeaderPrefix(t)); err != nil {
		t.Error(err)
	}
}

// The check must be able to fail: one literal changed at a time is red.
func TestEvidenceDigestsShape_CheckFailsOnADriftedCopy(t *testing.T) {
	deploy, _ := readLimitCopies(t)
	prefix := goHeaderPrefix(t)
	if err := digestsShapeError(deploy, prefix); err != nil {
		t.Fatalf("the real file is not equal to the Go definitions, so the negative cases below prove nothing: %v", err)
	}
	for _, c := range []struct{ name, old, repl string }{
		{"the header prefix (v1 to v2)", "EVIDENCE_DIGESTS_PREFIX='# falco-ctf evidence-digests v1 run='", "EVIDENCE_DIGESTS_PREFIX='# falco-ctf evidence-digests v2 run='"},
		{"the practice run id", "EVIDENCE_PRACTICE_RUN_ID='00000000000000000000000000000000'", "EVIDENCE_PRACTICE_RUN_ID='00000000000000000000000000000001'"},
		{"the run id length", "run=[0-9a-f]{32}$'", "run=[0-9a-f]{31}$'"},
		{"the run id alphabet", "run=[0-9a-f]{32}$'", "run=[0-9a-fA-F]{32}$'"},
		{"the header's end anchor", "run=[0-9a-f]{32}$'", "run=[0-9a-f]{32}'"},
		{"the digest length", "EVIDENCE_DIGEST_RE='^[0-9a-f]{64}$'", "EVIDENCE_DIGEST_RE='^[0-9a-f]{63}$'"},
		{"the digest's start anchor", "EVIDENCE_DIGEST_RE='^[0-9a-f]{64}$'", "EVIDENCE_DIGEST_RE='[0-9a-f]{64}$'"},
	} {
		if n := strings.Count(deploy, c.old); n != 1 {
			t.Fatalf("%s: the negative case's text %q must occur exactly once (%d times): rewording the line makes this check vacuous, update it", c.name, c.old, n)
		}
		drifted := strings.Replace(deploy, c.old, c.repl, 1)
		if err := digestsShapeError(drifted, prefix); err == nil {
			t.Errorf("deploy-user.sh: changing only %s was not detected", c.name)
		}
	}
	if err := digestsShapeError("", prefix); err == nil {
		t.Error("an empty deploy-user.sh was accepted")
	}
}
