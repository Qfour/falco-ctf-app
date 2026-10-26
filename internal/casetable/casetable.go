// Package casetable reads the shared grammar case tables (`input<TAB>accept|reject`)
// that every implementation of a grammar runs: internal/identity's seat-cases.tsv
// (app#480), internal/catalog/challengeid's challenge-id-cases.tsv (app#494),
// internal/catalog's scenario-name-cases.tsv (app#494) and the operator-input tables
// beside it (dns-suffix, image-registry, image-tag, api-server-cidr: app#510; dns-suffix's
// Go definition is internal/dnsname, ADR-0047, which runs it), and internal/ttydproxy's
// frame-ancestors-cases.tsv (app#520, ADR-0044). It is imported from test files only: no
// production binary links it.
//
// The format is the one the seat table's header spells out, and the shell reader
// (scripts/lib/casetable.sh, which scripts/check-seat-grammar.sh and
// scripts/check-deploy-user-ids.sh source: app#509) decodes the same closed
// placeholder set, so a row means the same input to every reader.
// TestShellPlaceholdersAreTheGoPlaceholders holds the two sets equal.
package casetable

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Row is one case: Line is its 1-based line in the file (for a failure message).
type Row struct {
	Line   int
	Input  string
	Accept bool
}

// placeholders are the characters a table cannot spell literally; the set is
// closed. A brace left after decoding is an unknown placeholder, an error of the
// reader, never a verdict: otherwise a reader that lacked a decoder would test
// the literal text, reject it, and stay green without trying the input the row
// stands for.
var placeholderPairs = []string{
	"{LF}", "\n",
	"{U+202E}", "\u202e",
	"{U+00FC}", "ü",
	"{U+00EF}", "ï",
}

var placeholders = strings.NewReplacer(placeholderPairs...)

// Parse reads the table text. It fails on any line that is not
// `input<TAB>accept|reject`, so a malformed row is red, not skipped.
func Parse(name, raw string) ([]Row, error) {
	var rows []Row
	for i, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First tab only: input may be empty (the line starts with a tab).
		in, verdict, ok := strings.Cut(line, "\t")
		if !ok || (verdict != "accept" && verdict != "reject") {
			return nil, fmt.Errorf("%s:%d: want exactly `input<TAB>accept|reject`, got %q", name, i+1, line)
		}
		if strings.ContainsAny(in, "\n\r") {
			return nil, fmt.Errorf("%s:%d: input spells a line break literally; use {LF}", name, i+1)
		}
		decoded := placeholders.Replace(in)
		if strings.ContainsAny(decoded, "{}") {
			return nil, fmt.Errorf("%s:%d: %q still contains a brace after decoding: an unknown placeholder", name, i+1, in)
		}
		rows = append(rows, Row{Line: i + 1, Input: decoded, Accept: verdict == "accept"})
	}
	return rows, nil
}

// Read reads and parses the table at path.
func Read(path string) ([]Row, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, string(raw))
}

// HeaderPrefix starts line 1 of a table: `# pattern: ` and the regex, the
// canonical literal of the grammar for every reader outside this repo.
const HeaderPrefix = "# pattern: "

// Header returns the regex on line 1 of the table text, and false when line 1 is
// not `# pattern: <regex>`.
func Header(raw string) (string, bool) {
	first, _, _ := strings.Cut(raw, "\n")
	return strings.CutPrefix(first, HeaderPrefix)
}

// ShellAssign returns the value of the single-quoted assignment `NAME='...'` that
// must stand exactly once, on a line of its own, in the shell source src. It is
// how a test holds a shell copy of a grammar equal to its definition; an
// indented, unquoted, doubled or missing assignment is "not found" (false), so a
// copy that moved out of reach of the check is red, not silently unchecked.
func ShellAssign(src, name string) (string, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `='([^'\n]*)'$`)
	m := re.FindAllStringSubmatch(src, -1)
	if len(m) != 1 {
		return "", false
	}
	return m[0][1], true
}

// dqEscape is a backslash before one of the four characters bash unescapes inside
// double quotes.
var dqEscape = regexp.MustCompile(`\\[$"\\` + "`" + `]`)

// ShellAssignDouble is ShellAssign for a grammar that contains a single quote (a CSP
// keyword such as 'none'), which a single-quoted shell literal cannot hold: the
// assignment `NAME="..."` that must stand exactly once, on a line of its own, in src.
// It returns the text between the quotes only when bash would give that text back
// unchanged: no backtick, no `\` before `$` `"` `\` or a backtick, and no `$` except
// as the last character (a regex's end anchor, which bash keeps; a `\` before any other
// character, as in `\.`, is kept too). Anything bash would expand or unescape is "not
// found" (false), so a literal that reads differently to bash than to this test is red;
// that includes a value ending in a backslash (it would escape the closing quote).
func ShellAssignDouble(src, name string) (string, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `="([^"\n]*)"$`)
	m := re.FindAllStringSubmatch(src, -1)
	if len(m) != 1 {
		return "", false
	}
	v := m[0][1]
	// A value ending in `\` makes the closing quote an escaped one: bash reads on, so the
	// line is not the assignment this regexp saw (a trailing `\\` is caught by dqEscape).
	if strings.HasSuffix(v, `\`) || strings.ContainsAny(v, "`") || strings.Contains(strings.TrimSuffix(v, "$"), "$") ||
		dqEscape.MatchString(v) {
		return "", false
	}
	return v, true
}
