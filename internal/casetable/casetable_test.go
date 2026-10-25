package casetable

import "testing"

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
