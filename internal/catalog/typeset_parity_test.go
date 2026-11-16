package catalog_test

// ADR-0056 V23: the closed set of `type:` values is written in three places, and
// two of them are shell. The catalog (Go) is the definition; the challenge image's
// missions-builder (images/challenge/Dockerfile) and the host-side V2 check of
// ADR-0026 (scripts/check-image-hygiene.sh) each carry a copy as `case` patterns
// and in their error text. A type added to the catalog and missed in a copy would
// build an image that refuses the challenge (or a V2 that passes a type the builder
// reads differently), and neither shows up until `make build`. This test reads the
// two files as text and holds their sets to catalog.Types.
//
// Same style as challengeid/shell_cases_test.go (the grammar's shell copy) and
// contracttable (the Makefile's build line): the shell source is data to a Go test.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// The shell copies, relative to this package's directory.
var typeSetSources = []string{
	filepath.Join("..", "..", "images", "challenge", "Dockerfile"),
	filepath.Join("..", "..", "scripts", "check-image-hygiene.sh"),
}

var (
	// a `case` pattern line: 'type: a'|'type: b') ...
	typeCaseLineRE = regexp.MustCompile(`^\s*('type: [a-z]+'(?:\|'type: [a-z]+')*)\)`)
	typeCaseWordRE = regexp.MustCompile(`'type: ([a-z]+)'`)
	// the alternation written in a comment or an error message: type: a|b|c
	typeListRE = regexp.MustCompile("type: ([a-z]+(?:\\|[a-z]+)+)")
)

// shellTypeSets extracts, from one shell source, the types its `case` pattern
// lines accept and every `type: a|b|c` list it prints or documents.
func shellTypeSets(src string) (caseSet []string, lists [][]string) {
	seen := map[string]struct{}{}
	for _, line := range strings.Split(src, "\n") {
		m := typeCaseLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, w := range typeCaseWordRE.FindAllStringSubmatch(m[1], -1) {
			seen[w[1]] = struct{}{}
		}
	}
	for t := range seen {
		caseSet = append(caseSet, t)
	}
	sort.Strings(caseSet)
	for _, m := range typeListRE.FindAllStringSubmatch(src, -1) {
		l := strings.Split(m[1], "|")
		sort.Strings(l)
		lists = append(lists, l)
	}
	return caseSet, lists
}

// checkTypeSets is the whole rule: an extraction that finds nothing is a failure
// (never "no difference"), and every set found equals want (sorted).
func checkTypeSets(name, src string, want []string) error {
	caseSet, lists := shellTypeSets(src)
	if len(caseSet) == 0 {
		return fmt.Errorf("%s: no `case` pattern line of the form 'type: x') was found: the extraction is broken or the rule moved", name)
	}
	if !slices.Equal(caseSet, want) {
		return fmt.Errorf("%s: case patterns accept %v, the catalog's types are %v", name, caseSet, want)
	}
	if len(lists) == 0 {
		return fmt.Errorf("%s: no `type: a|b|c` list (comment or error message) was found", name)
	}
	for _, l := range lists {
		if !slices.Equal(l, want) {
			return fmt.Errorf("%s: a `type: a|b|c` list names %v, the catalog's types are %v", name, l, want)
		}
	}
	return nil
}

func wantTypes() []string {
	want := catalog.Types()
	sort.Strings(want)
	return want
}

func TestTypeSet_ShellCopiesMatchTheCatalog(t *testing.T) {
	want := wantTypes()
	if len(want) != 4 || !slices.Contains(want, catalog.TypeInvestigate) {
		t.Fatalf("catalog.Types() = %v: expected the 3 original types and %q", want, catalog.TypeInvestigate)
	}
	for _, path := range typeSetSources {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTypeSets(path, string(raw), want); err != nil {
			t.Error(err)
		}
	}
}

// The check itself must be able to fail: each copy with `investigate` removed from
// one place (a case pattern, or a printed list) is red, and an extraction that finds
// nothing is red rather than "equal".
func TestTypeSet_ParityCheckFailsOnADriftedCopy(t *testing.T) {
	want := wantTypes()
	// the same removals, applied to every real source; each must change the text
	removals := []struct{ what, cut string }{
		{"the case pattern", "|'type: investigate'"},
		{"the printed or commented list", "|investigate"},
	}
	for _, path := range typeSetSources {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		for _, r := range removals {
			what, cut := r.what, r.cut
			if !strings.Contains(src, cut) {
				t.Errorf("%s: %s: the negative test's cut %q matches nothing (rewording the shell rule makes this check vacuous: update it)", path, what, cut)
				continue
			}
			// every occurrence of that form is removed: one place left alone would
			// leave the other copies green and prove nothing
			mutated := strings.ReplaceAll(src, cut, "")
			if err := checkTypeSets(path, mutated, want); err == nil {
				t.Errorf("%s: dropping investigate from %s was not detected", path, what)
			}
		}
		// one printed list alone, the others intact
		if i := strings.Index(src, "|investigate"); i >= 0 {
			one := src[:i] + src[i+len("|investigate"):]
			if err := checkTypeSets(path, one, want); err == nil {
				t.Errorf("%s: dropping investigate from a single place was not detected", path)
			}
		}
		// an extra type that only the copy knows
		extra := strings.Replace(src, "'type: detect'", "'type: detect'|'type: bogus'", 1)
		if extra == src {
			t.Errorf("%s: no 'type: detect' case pattern to extend", path)
		} else if err := checkTypeSets(path, extra, want); err == nil {
			t.Errorf("%s: an extra case pattern was not detected", path)
		}
	}
	for name, src := range map[string]string{"empty": "", "no case lines": "echo type: trigger|evade|detect|investigate\n"} {
		if err := checkTypeSets(name, src, want); err == nil {
			t.Errorf("%s source was accepted: an empty extraction must fail", name)
		}
	}
}

// ADR-0056 V23, A3b-2: the scoreboard spec carries the same closed set in four more
// places, because a response now names an investigate challenge: the `type` enum of
// MissionSummary, MissionDetail and ChallengeStat, and the `kind` of
// scoreboard_solves_total in the /metrics description. A generated Go type and a
// client switch follow the spec, so a copy that lacks a type is a response the
// spec says cannot happen. Each is held to catalog.Types() as the shell copies are.

var specTypeSetFile = filepath.Join("..", "..", "docs", "openapi-scoreboard.yaml")

// specTypeEnumSchemas are the schemas whose `type` property is the challenge-type enum.
var specTypeEnumSchemas = []string{"ChallengeStat", "MissionDetail", "MissionSummary"}

// the metric's kind list in the /metrics description: kind in {a, b, c}
var specKindRE = regexp.MustCompile(`kind in \{([a-z, ]+)\}`)

// checkSpecTypeSets loads the spec at path and requires every copy above to equal
// want (sorted). A copy that cannot be found is a failure, never "equal".
func checkSpecTypeSets(path string, want []string) error {
	spec, err := specparity.LoadSpec(path)
	if err != nil {
		return err
	}
	for _, name := range specTypeEnumSchemas {
		sch := spec.SchemaByName(name)
		if sch == nil {
			return fmt.Errorf("%s: no components.schemas.%s", path, name)
		}
		raw, _ := spec.PropertySchema(sch, "type")["enum"].([]any)
		if len(raw) == 0 {
			return fmt.Errorf("%s: %s.type has no enum", path, name)
		}
		got := make([]string, 0, len(raw))
		for _, v := range raw {
			s, _ := v.(string)
			got = append(got, s)
		}
		sort.Strings(got)
		if !slices.Equal(got, want) {
			return fmt.Errorf("%s: %s.type enum is %v, the catalog's types are %v", path, name, got, want)
		}
	}
	desc, _ := spec.Operations()["GET /metrics"]["description"].(string)
	lists := specKindRE.FindAllStringSubmatch(desc, -1)
	if len(lists) != 1 {
		return fmt.Errorf("%s: GET /metrics description has %d `kind in {...}` lists, want exactly 1 (scoreboard_solves_total)", path, len(lists))
	}
	var kinds []string
	for _, k := range strings.Split(lists[0][1], ",") {
		if k = strings.TrimSpace(k); k != "" {
			kinds = append(kinds, k)
		}
	}
	sort.Strings(kinds)
	if !slices.Equal(kinds, want) {
		return fmt.Errorf("%s: scoreboard_solves_total kind is %v, the catalog's types are %v", path, kinds, want)
	}
	return nil
}

func TestTypeSet_SpecCopiesMatchTheCatalog(t *testing.T) {
	if err := checkSpecTypeSets(specTypeSetFile, wantTypes()); err != nil {
		t.Error(err)
	}
}

// The spec check must be able to fail: `investigate` removed from any one of the
// four copies (a copy of the spec in a temp dir) is red, an extra type is red, and a
// spec without the lists it looks for is red rather than "equal".
func TestTypeSet_SpecParityCheckFailsOnADriftedCopy(t *testing.T) {
	want := wantTypes()
	raw, err := os.ReadFile(specTypeSetFile)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	write := func(name, text string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// nth replaces the nth (0-based) occurrence of old in s and fails the test if
	// there is none: a reworded spec must not turn this into a check of nothing.
	nth := func(s, old, repl string, n int) string {
		i := -1
		for k := 0; k <= n; k++ {
			j := strings.Index(s[i+1:], old)
			if j < 0 {
				t.Fatalf("occurrence %d of %q is not in the spec: update this negative test", n, old)
			}
			i += 1 + j
		}
		return s[:i] + repl + s[i+len(old):]
	}
	const enumLine = "enum: [trigger, evade, detect, investigate]"
	if got := strings.Count(src, enumLine); got != len(specTypeEnumSchemas) {
		t.Fatalf("the spec has %d `%s` lines, want %d (one per schema in specTypeEnumSchemas)", got, enumLine, len(specTypeEnumSchemas))
	}
	cases := map[string]string{}
	for i := range specTypeEnumSchemas {
		cases[fmt.Sprintf("investigate removed from enum copy %d", i)] = nth(src, enumLine, "enum: [trigger, evade, detect]", i)
	}
	cases["investigate removed from the metric's kind"] = nth(src, "kind in {trigger, evade, detect, investigate}", "kind in {trigger, evade, detect}", 0)
	cases["an extra type in an enum"] = nth(src, enumLine, "enum: [trigger, evade, detect, investigate, bogus]", 0)
	cases["an extra kind"] = nth(src, "kind in {trigger, evade, detect, investigate}", "kind in {trigger, evade, detect, investigate, bogus}", 0)
	cases["no kind list at all"] = nth(src, "kind in {trigger, evade, detect, investigate}", "kinds are listed elsewhere", 0)
	for name, text := range cases {
		if err := checkSpecTypeSets(write("spec.yaml", text), want); err == nil {
			t.Errorf("%s: the drifted copy was accepted", name)
		}
	}
	if err := checkSpecTypeSets(write("empty.yaml", "openapi: 3.1.0\n"), want); err == nil {
		t.Error("a spec with no schemas was accepted: an empty extraction must fail")
	}
}

// Types is the list parseFile accepts: each member loads from a minimal file, and
// a name outside it does not. Without this, Types could drift from the switch it
// claims to describe, and the shell parity above would hold the shell to the wrong set.
func TestTypes_IsExactlyWhatParseFileAccepts(t *testing.T) {
	minimal := map[string]string{
		catalog.TypeTrigger:     "type: trigger\nexpectedRules: [r]\n",
		catalog.TypeEvade:       "type: evade\nexpectedFlag: FALCO{dev-x}\n",
		catalog.TypeDetect:      "type: detect\ndetect: {evasionCapture: a.scap, benignCapture: b.scap}\n",
		catalog.TypeInvestigate: inv("", evMount(invMount), invHexQ),
	}
	for _, ty := range catalog.Types() {
		yaml, ok := minimal[ty]
		if !ok {
			t.Errorf("catalog.Types() has %q and this test has no minimal file for it", ty)
			continue
		}
		dir := t.TempDir()
		writeChallenge(t, dir, "01-a", yaml)
		cat, err := catalog.Load(dir)
		if err != nil {
			t.Errorf("type %q: %v", ty, err)
			continue
		}
		if cat["01-a"].Type != ty {
			t.Errorf("type %q loaded as %q", ty, cat["01-a"].Type)
		}
	}
	if len(minimal) != len(catalog.Types()) {
		t.Errorf("the test knows %d types, catalog.Types() has %d", len(minimal), len(catalog.Types()))
	}
	dir := t.TempDir()
	writeChallenge(t, dir, "01-a", "type: quiz\n")
	if _, err := catalog.Load(dir); err == nil {
		t.Error("an unknown type loaded")
	}
}
