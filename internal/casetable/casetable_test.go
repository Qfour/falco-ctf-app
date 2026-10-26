package casetable

import (
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestParse_PlaceholdersAndTheEmptyFirstColumn(t *testing.T) {
	rows, err := Parse("x", "# c\n\n\treject\nab{LF}\treject\nab{U+202E}\treject\n{U+00FC}{U+00EF}\treject\nab\taccept\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 || rows[0].Input != "" || rows[1].Input != "ab\n" || rows[2].Input != "ab\u202e" ||
		rows[3].Input != "üï" || !rows[4].Accept || rows[4].Line != 7 {
		t.Fatalf("placeholders, the empty first column or the line numbers were misread: %+v", rows)
	}
}

func TestParse_FailsOnAMalformedRow(t *testing.T) {
	for _, bad := range []string{"ab", "ab\tmaybe", "ab\taccept\textra", "ab\t", "ab\r\taccept",
		"ab{U+2028}\treject", "{LF\treject", "ab}\treject", "{lf}ab\treject"} {
		if _, err := Parse("x", bad+"\n"); err == nil {
			t.Errorf("%q was read as a valid row", bad)
		}
	}
}

func TestHeader(t *testing.T) {
	if got, ok := Header("# pattern: ^a$\nab\taccept\n"); !ok || got != "^a$" {
		t.Errorf("Header = %q, %v", got, ok)
	}
	for _, bad := range []string{"", "#pattern: ^a$\n", "\n# pattern: ^a$\n", " # pattern: ^a$\n"} {
		if _, ok := Header(bad); ok {
			t.Errorf("%q was read as a header", bad)
		}
	}
	// The header is a comment to the row reader, and no row is lost to it.
	rows, err := Parse("x", "# pattern: ^a$\nab\taccept\n")
	if err != nil || len(rows) != 1 {
		t.Errorf("header + one row read as %d rows, err %v", len(rows), err)
	}
}

func TestShellAssign(t *testing.T) {
	ok := "x\nNAME='^a{1}$'\ny\n"
	if got, found := ShellAssign(ok, "NAME"); !found || got != "^a{1}$" {
		t.Fatalf("a faithful assignment was not read back: %q, %v", got, found)
	}
	for name, src := range map[string]string{
		"missing":   "x\n",
		"twice":     ok + ok,
		"indented":  "  NAME='^a$'\n",
		"unquoted":  "NAME=^a$\n",
		"double":    "NAME=\"^a$\"\n",
		"in a line": "echo NAME='^a$'\n",
		"other":     "OTHER_NAME='^a$'\n",
		"suffix":    "NAME='^a$' # c\n",
	} {
		if _, found := ShellAssign(src, "NAME"); found {
			t.Errorf("%s: read as a single definition", name)
		}
	}
}

func TestShellAssignDouble(t *testing.T) {
	ok := "x\nNAME=\"^('none'|a\\.b)$\"\ny\n"
	if got, found := ShellAssignDouble(ok, "NAME"); !found || got != `^('none'|a\.b)$` {
		t.Fatalf("a faithful assignment was not read back: %q, %v", got, found)
	}
	for name, src := range map[string]string{
		"missing":           "x\n",
		"twice":             ok + ok,
		"indented":          "  NAME=\"^a$\"\n",
		"single quoted":     "NAME='^a$'\n",
		"unquoted":          "NAME=^a$\n",
		"in a line":         "echo NAME=\"^a$\"\n",
		"other":             "OTHER_NAME=\"^a$\"\n",
		"suffix":            "NAME=\"^a$\" # c\n",
		"expansion":         "NAME=\"^a$HOME\"\n",
		"command subst":     "NAME=\"^a$(id)\"\n",
		"dollar mid":        "NAME=\"^a$|b$\"\n",
		"backtick":          "NAME=\"^a`id`$\"\n",
		"escaped dollar":    "NAME=\"^a\\$\"\n",
		"escaped quote":     "NAME=\"^a\\\"b$\"\n",
		"escaped backslash": "NAME=\"^a\\\\.b$\"\n",
	} {
		if _, found := ShellAssignDouble(src, "NAME"); found {
			t.Errorf("%s: read as a single definition bash would give back unchanged", name)
		}
	}
}

// The shell reader (scripts/lib/casetable.sh, app#509) decodes the same closed
// placeholder set. If the two sets drifted, a row would stand for one input in Go and
// another in shell, or be a verdict in one reader and an unknown-placeholder error in
// the other. The shell side is read as text: CT_PLACEHOLDERS lists the names on one
// line, and ct_decode must hold one substitution per name (test-casetable-lib.sh
// holds what each decodes to, in bytes).
func TestShellPlaceholdersAreTheGoPlaceholders(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/lib/casetable.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	list, ok := ShellAssign(src, "CT_PLACEHOLDERS")
	if !ok {
		t.Fatal("scripts/lib/casetable.sh has no single-quoted CT_PLACEHOLDERS='...' line of its own")
	}
	shell := strings.Fields(list)
	var goNames []string
	for i := 0; i < len(placeholderPairs); i += 2 {
		name, value := placeholderPairs[i], placeholderPairs[i+1]
		goNames = append(goNames, name)
		// A {U+XXXX} name is the code point it says: the table's own spelling.
		if hex, ok := strings.CutPrefix(strings.TrimSuffix(name, "}"), "{U+"); ok {
			cp, err := strconv.ParseUint(hex, 16, 32)
			if err != nil || value != string(rune(cp)) {
				t.Errorf("%s decodes to %q in Go, not the code point it names", name, value)
			}
		}
	}
	sort.Strings(goNames)
	sortedShell := append([]string(nil), shell...)
	sort.Strings(sortedShell)
	if !slices.Equal(goNames, sortedShell) {
		t.Fatalf("placeholder sets differ: Go %v, scripts/lib/casetable.sh CT_PLACEHOLDERS %v", goNames, sortedShell)
	}
	// ct_decode has exactly one substitution per name (a name listed but not
	// decoded would be left as a brace and read as an unknown placeholder).
	for _, name := range shell {
		sub := `DECODED="${DECODED//` + strings.NewReplacer("{", `\{`, "}", `\}`).Replace(name) + `/`
		if strings.Count(src, sub) != 1 {
			t.Errorf("ct_decode has %d substitutions for %s, want 1", strings.Count(src, sub), name)
		}
	}
	if n := strings.Count(src, "DECODED=\"${DECODED//"); n != len(shell) {
		t.Errorf("ct_decode has %d substitutions, CT_PLACEHOLDERS lists %d names", n, len(shell))
	}
}
