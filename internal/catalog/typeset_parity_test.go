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
