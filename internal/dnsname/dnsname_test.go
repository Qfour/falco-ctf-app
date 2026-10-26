package dnsname_test

// ADR-0047 (app#533): the DNS name grammar has ONE Go definition, dnsname.Pattern and
// dnsname.MaxLen. charts/ctf-user/deploy-user.sh holds a shell copy of each
// (DNS_SUFFIX_PATTERN / DNS_SUFFIX_MAX_LEN, the grammar of --dns-suffix and --app-host)
// and internal/catalog/testdata/dns-suffix-cases.tsv holds the pattern as its
// `# pattern: ` header (platform reads that line). This file holds the three equal, runs
// every row of the table through Valid, requires the chart's default to pass, and holds
// the package to the standard library. scripts/check-deploy-user-ids.sh runs the same
// rows through deploy-user.sh itself.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
	"github.com/Qfour/falco-ctf-app/internal/dnsname"
)

const tableFile = "dns-suffix-cases.tsv"

var tablePath = filepath.Join("..", "catalog", "testdata", tableFile)

func readFile(t *testing.T, path ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// V1: the Go constant, the shell literal and the table's header are one text, and
// the bound is 253 in Go and in the shell: a change to one alone is red here.
func TestDNSName_OneDefinition(t *testing.T) {
	script := readFile(t, "..", "..", "charts", "ctf-user", "deploy-user.sh")
	header, ok := casetable.Header(readFile(t, tablePath))
	if !ok {
		t.Fatalf("%s line 1 must be %q followed by the regex", tableFile, casetable.HeaderPrefix)
	}
	if header != dnsname.Pattern {
		t.Errorf("%s header = %q, want dnsname.Pattern %q", tableFile, header, dnsname.Pattern)
	}
	shell, ok := casetable.ShellAssign(script, "DNS_SUFFIX_PATTERN")
	if !ok {
		t.Fatal("deploy-user.sh must define DNS_SUFFIX_PATTERN='...' exactly once on its own line")
	}
	if shell != dnsname.Pattern {
		t.Errorf("deploy-user.sh DNS_SUFFIX_PATTERN = %q, want dnsname.Pattern %q", shell, dnsname.Pattern)
	}
	maxLit, ok := casetable.ShellAssign(script, "DNS_SUFFIX_MAX_LEN")
	if !ok {
		t.Fatal("deploy-user.sh must define DNS_SUFFIX_MAX_LEN='...' exactly once on its own line")
	}
	if maxLit != "253" || dnsname.MaxLen != 253 {
		t.Errorf("DNS_SUFFIX_MAX_LEN = %q, dnsname.MaxLen = %d, want 253 (RFC 1123)", maxLit, dnsname.MaxLen)
	}
}

// The constants compose: Pattern is Body between its anchors, and Body repeats Label
// (the one literal) joined by a dot. A hand-edited Pattern that stopped being the
// anchored Body is red.
func TestDNSName_Composition(t *testing.T) {
	if dnsname.Pattern != "^"+dnsname.Body+"$" {
		t.Errorf("Pattern = %q, want ^Body$", dnsname.Pattern)
	}
	if dnsname.Body != dnsname.Label+`(\.`+dnsname.Label+`)*` {
		t.Errorf("Body = %q, want Label (\\. Label)*", dnsname.Body)
	}
}

// Every row of the shared table, through Valid (the pattern and the bound together).
func TestDNSName_SharedCaseTable(t *testing.T) {
	rows, err := casetable.Read(tablePath)
	if err != nil {
		t.Fatal(err)
	}
	accepted, rejected := 0, 0
	has253, has254, has63, has64 := false, false, false, false
	for _, r := range rows {
		if r.Accept {
			accepted++
		} else {
			rejected++
		}
		if got := dnsname.Valid(r.Input); got != r.Accept {
			t.Errorf("%s:%d: Valid(%q) = %v, want %v", tableFile, r.Line, r.Input, got, r.Accept)
		}
		switch {
		case len(r.Input) == 253 && r.Accept:
			has253 = true
		case len(r.Input) == 254 && !r.Accept:
			has254 = true
		case len(r.Input) == 63 && r.Accept:
			has63 = true
		case len(r.Input) == 64 && !r.Accept:
			has64 = true
		}
	}
	if len(rows) < 50 || accepted < 15 || rejected < 30 {
		t.Fatalf("%s has %d rows (%d accept / %d reject): the table was truncated or misread", tableFile, len(rows), accepted, rejected)
	}
	if !has253 || !has254 || !has63 || !has64 {
		t.Errorf("%s lacks a row at an edge: 253 accept %v, 254 reject %v, 63 accept %v, 64 reject %v", tableFile, has253, has254, has63, has64)
	}
}

// The edges, built here rather than read from the table: a label of 63 characters is a
// name and one of 64 is not; a name of 253 characters is one and 254 is not (the pattern
// accepts 254, only the bound refuses it); the empty string is not a name.
func TestDNSName_Edges(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	// 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
	whole253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	whole254 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 62)
	if len(whole253) != 253 || len(whole254) != 254 {
		t.Fatalf("the fixtures are %d and %d characters, want 253 and 254", len(whole253), len(whole254))
	}
	for name, c := range map[string]struct {
		in   string
		want bool
	}{
		"label of 63":             {label63, true},
		"label of 64":             {label64, false},
		"label of 64 after a dot": {"a." + label64, false},
		"whole name of 253":       {whole253, true},
		"whole name of 254":       {whole254, false},
		"empty":                   {"", false},
		"one character":           {"a", true},
		"trailing newline":        {"a.example\n", false},
		"upper case":              {"A.example", false},
		"trailing dot":            {"a.example.", false},
		"port":                    {"a.example:443", false},
	} {
		if got := dnsname.Valid(c.in); got != c.want {
			t.Errorf("%s: Valid(%q) = %v, want %v", name, c.in, got, c.want)
		}
	}
	if !regexp.MustCompile(dnsname.Pattern).MatchString(whole254) {
		t.Error("the 254-character fixture no longer matches Pattern: the test of the bound tests nothing (a regexp cannot count the whole)")
	}
}

// What the chart ships with must pass the grammar: a grammar tightened past the default
// is red here, not at a stand-up that passes the default through.
func TestDNSName_ChartDefaultIsAccepted(t *testing.T) {
	values := readFile(t, "..", "..", "charts", "ctf-user", "values.yaml")
	m := regexp.MustCompile(`(?m)^dnsSuffix:\s*"([^"\n]*)"\s*$`).FindStringSubmatch(values)
	if m == nil {
		t.Fatal("values.yaml has no top-level dnsSuffix: \"...\" line: the test's reader is stale")
	}
	if !dnsname.Valid(m[1]) {
		t.Errorf("chart default dnsSuffix %q is not a dnsname.Valid name", m[1])
	}
}

// V3: dnsname is a leaf, the standard library only. ttyd-proxy's distroless image copies
// it by name (images/ttyd-proxy/Dockerfile), and a package of this module or a third
// party in it would widen what that image links and what its SBOM carries.
func importsOnlyStdlib(name string, src any) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
			bad = append(bad, path)
		}
	}
	return bad, nil
}

func TestDNSNameImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		bad, err := importsOnlyStdlib(name, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, path := range bad {
			t.Errorf("%s imports %q: dnsname may import the standard library only", name, path)
		}
	}
	if seen == 0 {
		t.Fatal("no non-test file found; the check would pass on nothing")
	}
}

func TestStdlibImportCheck_CatchesAForeignImport(t *testing.T) {
	for name, src := range map[string]string{
		"a module package": "package x\nimport \"github.com/Qfour/falco-ctf-app/internal/identity\"\n",
		"a third party":    "package x\nimport \"gopkg.in/yaml.v3\"\n",
	} {
		if bad, err := importsOnlyStdlib("x.go", src); err != nil || len(bad) != 1 {
			t.Errorf("%s: not found: %v, %v", name, bad, err)
		}
	}
	if bad, _ := importsOnlyStdlib("x.go", "package x\nimport (\n\t\"regexp\"\n\t\"net/http\"\n)\n"); len(bad) != 0 {
		t.Errorf("a standard library import was reported: %v", bad)
	}
}
