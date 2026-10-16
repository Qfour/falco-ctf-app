package view

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/dop251/goja"
	"gopkg.in/yaml.v3"
)

// The Profile form's display-name check (nameProblem / trimName / planSave in
// pane-me.tmpl), RUN, not string-matched (app#331, app#343).
//
// The functions and constants are cut out of the SOURCE partial the way
// scripts/check-portal-render.sh does it (a function from "\n  function name("
// to the next "\n  }\n"; a constant is one "  const NAME = ...;" line) and run
// in goja, a pure-Go ECMAScript engine (a test-only dependency: go.sum pins it,
// no cgo, no apk package, no jsc/node on PATH, and no skip when one is absent;
// internal/apispec's boundary test keeps it out of every cmd/* binary). The
// same rows as the server's test (api/testdata/display-name-parity/cases.yaml)
// are fed through planSave and compared with the table's `client` column, so a
// form that refuses what the server accepts fails here; the table's own server
// column is checked against validDisplayName by api/display_name_parity_test.go.
//
// What this is not: a browser. goja has its own regexp engine and takes its
// \p{Cc}/\p{Cf} tables from Go's unicode package, so the sweep below proves the
// form's STRUCTURE (the ZWJ exception, the trim set, the metacharacters) against
// Go's tables; a browser whose Unicode version is newer than Go's could still
// refuse a freshly assigned Cf the server accepts (a residual; the layout and
// the click handler are the e2e harness's, ADR-0031).

func extractJSFunc(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n  function "+name+"(")
	if start < 0 {
		t.Fatalf("pane-me.tmpl: function %s not found (the test cuts it out of the source)", name)
	}
	end := strings.Index(src[start+1:], "\n  }\n")
	if end < 0 {
		t.Fatalf("pane-me.tmpl: function %s has no closing brace at 2-space indent", name)
	}
	return src[start+1 : start+1+end+len("\n  }")]
}

func extractJSConst(t *testing.T, src, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^  const ` + name + ` = .*;$`).FindString(src)
	if m == "" {
		t.Fatalf("pane-me.tmpl: single-line const %s not found", name)
	}
	return m
}

// nameRulesJS is the form's rule, cut out of pane-me.tmpl.
func nameRulesJS(t *testing.T) string {
	t.Helper()
	src := partialBody(portalPartials(t), "pane-me.tmpl")
	var b strings.Builder
	for _, c := range []string{"NAME_EDGE_SPACE", "NAME_HTML_META", "NAME_HIDDEN"} {
		b.WriteString(extractJSConst(t, src, c) + "\n")
	}
	for _, f := range []string{"trimName", "nameProblem", "planSave"} {
		b.WriteString(extractJSFunc(t, src, f) + "\n")
	}
	return b.String()
}

// runJS runs rules + a driver in a fresh goja VM. globals are set first (Go
// strings become JS strings, any code point intact). The driver leaves its
// answer in the variable `out`; it is decoded from JSON.
func runJS(t *testing.T, rules, driver string, globals map[string]any, into any) {
	t.Helper()
	vm := goja.New()
	for k, v := range globals {
		if err := vm.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := vm.RunString(rules + "\n" + driver); err != nil {
		t.Fatalf("running the form's name rules: %v", err)
	}
	v, err := vm.RunString("JSON.stringify(out)")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(v.String()), into); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%.300s", err, v.String())
	}
}

type nameParityCase struct {
	Name   string  `yaml:"name" json:"name"`
	Repeat int     `yaml:"repeat" json:"-"`
	Server string  `yaml:"server" json:"-"`
	Client string  `yaml:"client" json:"-"`
	Stored *string `yaml:"stored" json:"-"`
	Note   string  `yaml:"note" json:"-"`
}

func (c nameParityCase) input() string {
	if c.Repeat > 0 {
		return strings.Repeat(c.Name, c.Repeat)
	}
	return c.Name
}

func loadNameParityCases(t *testing.T) []nameParityCase {
	t.Helper()
	raw, err := os.ReadFile("../api/testdata/display-name-parity/cases.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []nameParityCase `yaml:"cases"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("cases.yaml: %v", err)
	}
	if len(f.Cases) < 17 {
		t.Fatalf("cases.yaml: %d rows, want at least 17", len(f.Cases))
	}
	return f.Cases
}

type planResult struct {
	Problem string            `json:"problem"`
	Body    map[string]string `json:"body"`
}

const nameplanDriver = `
var out = CASES.map(function (name) {
  var p = planSave(name, SAVED_NAME, 'fox', 'fox');
  return { problem: p.problem || '', body: p.body || null };
});
`

// TestNameProblem_AnswersTheSharedTable: for every row of the table shared with
// the server's test, the form's answer is the `client` column, and an accepted
// name is trimmed to exactly what the server stores. A row with
// `client: reject, server: accept` is a form stricter than the server: the
// contract is zero of them.
func TestNameProblem_AnswersTheSharedTable(t *testing.T) {
	cases := loadNameParityCases(t)
	var inputs []string
	for _, c := range cases {
		inputs = append(inputs, c.input())
	}
	var got []planResult
	runJS(t, nameRulesJS(t), nameplanDriver, map[string]any{"SAVED_NAME": "(saved name)", "CASES": inputs}, &got)
	if len(got) != len(cases) {
		t.Fatalf("driver answered %d rows, want %d", len(got), len(cases))
	}
	var clientOnlyReject, clientReject, serverReject int
	for i, c := range cases {
		in := c.input()
		rejected := got[i].Problem != ""
		if c.Server == "reject" {
			serverReject++
		}
		if rejected {
			clientReject++
		}
		if rejected && c.Server == "accept" {
			clientOnlyReject++
			t.Errorf("%s: the form refuses %+q, which the server accepts: %q", c.Note, in, got[i].Problem)
			continue
		}
		if rejected != (c.Client == "reject") {
			t.Errorf("%s: form answered %v (%q) for %+q; the table says client: %s", c.Note, rejected, got[i].Problem, in, c.Client)
			continue
		}
		if rejected {
			continue
		}
		want := in
		if c.Stored != nil {
			want = *c.Stored
		}
		if sent := got[i].Body["display_name"]; sent != want {
			t.Errorf("%s: the form would send %+q for %+q; the server stores %+q", c.Note, sent, in, want)
		}
	}
	if clientOnlyReject != 0 {
		t.Fatalf("client-only rejects = %d, want 0", clientOnlyReject)
	}
	t.Logf("rows=%d server-reject=%d client-reject=%d client-only-reject=%d", len(cases), serverReject, clientReject, clientOnlyReject)
}

// TestPlanSave_ChecksTheNameOnlyWhenItChanged: a saved name (it may predate
// the rule, or hold a character the form is stricter on) must not stop a change
// of avatar alone; a CHANGED name is always checked.
func TestPlanSave_ChecksTheNameOnlyWhenItChanged(t *testing.T) {
	const saved = "Ali\u200bce" // a saved name holding a zero-width space (stored before app#331)
	driver := `
var out = {
  avatarOnly:        planSave(SAVED, SAVED, 'owl', 'fox'),
  avatarOnlyPadded:  planSave('  ' + SAVED + '  ', SAVED, 'owl', 'fox'),
  nameChangedBad:    planSave('Ali\u200bc', SAVED, 'fox', 'fox'),
  nameChangedGood:   planSave('Alice', SAVED, 'fox', 'fox'),
  both:              planSave('Alice', SAVED, 'owl', 'fox'),
  nothing:           planSave(SAVED, SAVED, 'fox', 'fox'),
  emptyIsChanged:    planSave('   ', SAVED, 'fox', 'fox'),
  tooLongIsChanged:  planSave(new Array(34).join('a'), SAVED, 'fox', 'fox'),
  avatarWithBadName: planSave('<b>', SAVED, 'owl', 'fox'),
};
`
	var got map[string]planResult
	runJS(t, nameRulesJS(t), driver, map[string]any{"SAVED": saved}, &got)
	eq := func(label string, body map[string]string, want map[string]string) {
		t.Helper()
		if got[label].Problem != "" {
			t.Errorf("%s: unexpected problem %q", label, got[label].Problem)
			return
		}
		a, _ := json.Marshal(body)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			t.Errorf("%s: body %s, want %s", label, a, b)
		}
	}
	eq("avatarOnly", got["avatarOnly"].Body, map[string]string{"avatar": "owl"})
	eq("avatarOnlyPadded", got["avatarOnlyPadded"].Body, map[string]string{"avatar": "owl"})
	eq("nameChangedGood", got["nameChangedGood"].Body, map[string]string{"display_name": "Alice"})
	eq("both", got["both"].Body, map[string]string{"display_name": "Alice", "avatar": "owl"})
	eq("nothing", got["nothing"].Body, map[string]string{})
	for _, label := range []string{"nameChangedBad", "emptyIsChanged", "tooLongIsChanged", "avatarWithBadName"} {
		if got[label].Problem == "" {
			t.Errorf("%s: a changed name must be checked, but the form let it through", label)
		}
		if got[label].Body != nil {
			t.Errorf("%s: nothing may be sent when the name is refused, got %v", label, got[label].Body)
		}
	}
}

// TestNameProblem_SweepEveryCodePoint: for EVERY Unicode code point, the form
// refuses it (inside "a" + c + "b") exactly when the server's class does -- the
// ASCII metacharacters, \p{Cc}, \p{Cf} -- except U+200D, which the form always
// lets through; and the form's trim removes exactly the code points Go's
// strings.TrimSpace removes. The table covers chosen names; this covers all of
// Unicode, so a slip in the exception, the metacharacter class or the trim set
// cannot hide between the rows. (The engine takes \p{Cc}/\p{Cf} from Go's
// unicode tables, so this cannot see a browser with newer tables; see the top.)
func TestNameProblem_SweepEveryCodePoint(t *testing.T) {
	driver := `
var rejected = [], trimmed = [];
for (var cp = 0; cp <= 0x10FFFF; cp++) {
  if (cp >= 0xD800 && cp <= 0xDFFF) continue;   // surrogates are not code points
  if (cp >= 0x40000 && cp <= 0xDFFFF) continue; // planes 4-13: unassigned, no Cc/Cf (keeps the sweep to ~3 s)
  var ch = String.fromCodePoint(cp);
  if (nameProblem('a' + ch + 'b') !== '') rejected.push(cp);
  if (trimName(ch) === '') trimmed.push(cp);
}
var out = { rejected: rejected, trimmed: trimmed };
`
	var got struct {
		Rejected []int `json:"rejected"`
		Trimmed  []int `json:"trimmed"`
	}
	runJS(t, nameRulesJS(t), driver, nil, &got)

	var wantRej, wantTrim []int
	for cp := 0; cp <= unicode.MaxRune; cp++ {
		if (cp >= 0xD800 && cp <= 0xDFFF) || (cp >= 0x40000 && cp <= 0xDFFFF) {
			continue
		}
		r := rune(cp)
		if cp != 0x200D && (strings.ContainsRune(`<>&"'`, r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r)) {
			wantRej = append(wantRej, cp)
		}
		if strings.TrimSpace(string(r)) == "" {
			wantTrim = append(wantTrim, cp)
		}
	}
	diff := func(label string, got, want []int) {
		t.Helper()
		g, w := map[int]bool{}, map[int]bool{}
		for _, c := range got {
			g[c] = true
		}
		for _, c := range want {
			w[c] = true
		}
		var extra, missing []string
		for c := range g {
			if !w[c] {
				extra = append(extra, fmt.Sprintf("U+%04X", c))
			}
		}
		for c := range w {
			if !g[c] {
				missing = append(missing, fmt.Sprintf("U+%04X", c))
			}
		}
		sort.Strings(extra)
		sort.Strings(missing)
		if len(extra)+len(missing) > 0 {
			t.Errorf("%s differs from Go (unicode.Version %s): the form has but Go does not: %v; Go has but the form does not: %v",
				label, unicode.Version, extra, missing)
		}
	}
	diff("refused code points", got.Rejected, wantRej)
	diff("trimmed code points", got.Trimmed, wantTrim)
}

// TestNameProblem_ServerMessageStaysText pins what the form does with a failed
// save: the server's own sentence is read as a string and shown with
// textContent, never as markup (XSS), and a 400 shows it.
func TestNameProblem_ServerMessageStaysText(t *testing.T) {
	pane := partialBody(portalPartials(t), "pane-me.tmpl")
	for _, want := range []string{
		`failureSentence(r)`,
		`typeof j.error === 'string'`,
		`msgEl.textContent = text`,
		`planSave(nameInput.value, serverName, chosen, serverAvatar)`,
	} {
		if !strings.Contains(pane, want) {
			t.Errorf("pane-me.tmpl: want %s", want)
		}
	}
	// The pre-app#331 class and String.trim() must not come back: trim() is not
	// strings.TrimSpace (it keeps U+0085 and strips U+FEFF).
	for _, bad := range []string{`\x00-\x1f`, `nameInput.value.trim()`} {
		if strings.Contains(pane, bad) {
			t.Errorf("pane-me.tmpl still has %s", bad)
		}
	}
}
