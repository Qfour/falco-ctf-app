package view

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode"

	"gopkg.in/yaml.v3"
)

// The new-thread form's pre-check of the board subject (subjectProblem in
// pane-board.tmpl, with the shared trimName / hasHiddenChar of core-util.tmpl), RUN in
// goja the way portal_nameproblem_test.go runs the Profile name's (app#408, app#377).
// The server's 400 for a forbidden character is a fixed sentence that does not say
// which character, so the form names the kind and what to do; the contract is the
// display name's: the form is NEVER stricter than the server.
//
//   - TestSubjectProblem_AnswersTheSharedTable feeds the rows of
//     api/testdata/board-subject/cases.yaml (the table api/board_subject_rule_test.go
//     runs through validBoardSubject) and compares with each row's `client` column;
//     a row `client: reject, server: accept` is a form stricter than the server.
//   - TestSubjectProblem_SweepEveryCodePoint compares the form's refused set over every
//     code point with rule.yaml's `categories` (the metacharacters are legal in a subject).
//
// The same limits as the name test apply (goja takes \p{Cc}/\p{Cf} from Go's tables, so
// this proves the STRUCTURE, not a browser with newer tables).

// subjectRulesJS is the form's rule cut out of the source: trimName and hasHiddenChar from
// core-util.tmpl, MAX_SUBJECT_RUNES / runeLen / subjectProblem from pane-board.tmpl.
func subjectRulesJS(t *testing.T) string {
	t.Helper()
	parts := portalPartials(t)
	util, pane := partialBody(parts, "core-util.tmpl"), partialBody(parts, "pane-board.tmpl")
	var b strings.Builder
	for _, c := range []string{"trimName", "hasHiddenChar"} {
		b.WriteString(extractJSConst(t, util, c) + "\n")
	}
	b.WriteString(extractJSConst(t, pane, "MAX_SUBJECT_RUNES") + "\n")
	for _, f := range []string{"runeLen", "subjectProblem"} {
		b.WriteString(extractJSFunc(t, pane, f) + "\n")
	}
	return b.String()
}

type subjectCase struct {
	Name   string  `yaml:"name"`
	Repeat int     `yaml:"repeat"`
	Server string  `yaml:"server"`
	Error  string  `yaml:"error"`
	Client string  `yaml:"client"`
	Stored *string `yaml:"stored"`
	Note   string  `yaml:"note"`
}

func (c subjectCase) input() string {
	if c.Repeat > 0 {
		return strings.Repeat(c.Name, c.Repeat)
	}
	return c.Name
}

func loadSubjectCases(t *testing.T) []subjectCase {
	t.Helper()
	raw, err := os.ReadFile("../api/testdata/board-subject/cases.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []subjectCase `yaml:"cases"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("board-subject/cases.yaml: %v", err)
	}
	if len(f.Cases) < 20 {
		t.Fatalf("board-subject/cases.yaml: %d rows, want at least 20", len(f.Cases))
	}
	return f.Cases
}

// forbiddenInvisible is the subject's class: rule.yaml's categories only, no metacharacters.
func (r nameRule) forbiddenInvisible(c rune) bool {
	for _, cat := range r.Categories {
		if unicode.Is(unicode.Categories[cat], c) {
			return true
		}
	}
	return false
}

type subjectResult struct {
	Problem string `json:"problem"`
	Sent    string `json:"sent"` // what the form would send: the subject as trimName leaves it
}

// TestSubjectProblem_AnswersTheSharedTable: for every row of the table shared with the
// server's test, the form (trimName, then subjectProblem, as onCreateSubmit does) answers
// the `client` column, an accepted subject is trimmed to exactly what the server stores,
// and a refusal says something. Zero rows may be client-only rejects.
func TestSubjectProblem_AnswersTheSharedTable(t *testing.T) {
	cases := loadSubjectCases(t)
	var inputs []string
	for _, c := range cases {
		inputs = append(inputs, c.input())
	}
	driver := `
var out = CASES.map(function (raw) {
  var s = trimName(raw);
  return { problem: subjectProblem(s), sent: s };
});
`
	var got []subjectResult
	runJS(t, subjectRulesJS(t), driver, map[string]any{"CASES": inputs}, &got)
	if len(got) != len(cases) {
		t.Fatalf("driver answered %d rows, want %d", len(got), len(cases))
	}
	var clientOnlyReject int
	for i, c := range cases {
		in := c.input()
		rejected := got[i].Problem != ""
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
		if c.Server != "accept" {
			continue // the one allowed difference (ZWJ outside emoji): the server answers, the form passes
		}
		want := in
		if c.Stored != nil {
			want = *c.Stored
		}
		if got[i].Sent != want {
			t.Errorf("%s: the form would send %+q for %+q; the server stores %+q", c.Note, got[i].Sent, in, want)
		}
	}
	if clientOnlyReject != 0 {
		t.Fatalf("client-only rejects = %d, want 0", clientOnlyReject)
	}
}

// TestSubjectProblem_SaysWhatToDo pins the sentences a participant reads: each kind of
// refusal is told apart and the hidden-character one tells what to remove (the reason for
// the pre-check: the server's 400 does not name the character).
func TestSubjectProblem_SaysWhatToDo(t *testing.T) {
	driver := `
var out = {
  empty: subjectProblem(''),
  tooLong: subjectProblem(new Array(122).join('a')),
  tab: subjectProblem('a\tb'),
  ok: subjectProblem('fine'),
};
`
	var got map[string]string
	runJS(t, subjectRulesJS(t), driver, nil, &got)
	if got["ok"] != "" {
		t.Errorf("a plain subject is refused: %q", got["ok"])
	}
	for k, sub := range map[string]string{
		"empty":   "Enter a subject",
		"tooLong": "121 characters; the limit is 120",
		"tab":     "tab",
	} {
		if !strings.Contains(got[k], sub) {
			t.Errorf("%s: sentence %q lacks %q", k, got[k], sub)
		}
	}
	if !strings.Contains(got["tab"], "Remove") || !strings.Contains(got["tab"], "invisible") {
		t.Errorf("the hidden-character sentence must say to remove tabs and invisible characters: %q", got["tab"])
	}
}

// TestSubjectProblem_SweepEveryCodePoint: for EVERY code point, the form refuses
// "a"+c+"b" exactly when rule.yaml's categories (Cc, Cf) name it, except U+200D, which the
// form always passes (the server refuses it outside emoji), and the rule's metacharacters
// pass (a subject is prose). So "form == rule" and, with the server's own sweep
// (api/board_subject_rule_test.go), the form is never stricter than the server.
func TestSubjectProblem_SweepEveryCodePoint(t *testing.T) {
	driver := `
var rejected = [];
for (var cp = 0; cp <= 0x10FFFF; cp++) {
  if (cp >= 0xD800 && cp <= 0xDFFF) continue;   // surrogates are not code points
  if (cp >= 0x40000 && cp <= 0xDFFFF) continue; // planes 4-13: unassigned, no Cc/Cf (keeps the sweep short)
  if (subjectProblem('a' + String.fromCodePoint(cp) + 'b') !== '') rejected.push(cp);
}
var meta = [];
for (var i = 0; i < META.length; i++) if (subjectProblem('a' + META[i] + 'b') !== '') meta.push(META[i]);
var out = { rejected: rejected, meta: meta, zwj: subjectProblem('a\u200Db') };
`
	rule := loadNameRule(t)
	var got struct {
		Rejected []int    `json:"rejected"`
		Meta     []string `json:"meta"`
		ZWJ      string   `json:"zwj"`
	}
	runJS(t, subjectRulesJS(t), driver, map[string]any{"META": strings.Split(rule.Meta, "")}, &got)

	var want []int
	for cp := 0; cp <= unicode.MaxRune; cp++ {
		if (cp >= 0xD800 && cp <= 0xDFFF) || (cp >= 0x40000 && cp <= 0xDFFFF) {
			continue
		}
		if cp != rule.Exempt && rule.forbiddenInvisible(rune(cp)) {
			want = append(want, cp)
		}
	}
	g, w := map[int]bool{}, map[int]bool{}
	for _, c := range got.Rejected {
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
		t.Errorf("refused code points differ from rule.yaml (unicode.Version %s): the form has but the rule does not: %v; the rule has but the form does not: %v",
			unicode.Version, extra, missing)
	}
	if len(want) < 200 {
		t.Errorf("the rule names only %d code points; the sweep is not applying it", len(want))
	}
	if len(got.Meta) != 0 {
		t.Errorf("the form refuses metacharacters %q, which a subject (prose) may hold", got.Meta)
	}
	if got.ZWJ != "" {
		t.Errorf("the form refuses U+200D (%q); it must pass it and leave the emoji-adjacency rule to the server", got.ZWJ)
	}
}

// TestSubjectForm_UsesThePrecheckAndShowsTheServerSentenceAsText pins the wiring of
// onCreateSubmit (the click handler is the e2e harness's, ADR-0031): the subject is trimmed
// with trimName (not String.prototype.trim) and checked with subjectProblem BEFORE the
// fetch; a failure shows the server's sentence read as a string (serverErrorText) with
// textContent, never as markup.
func TestSubjectForm_UsesThePrecheckAndShowsTheServerSentenceAsText(t *testing.T) {
	pane := partialBody(portalPartials(t), "pane-board.tmpl")
	start := strings.Index(pane, "async function onCreateSubmit(")
	if start < 0 {
		t.Fatal("pane-board.tmpl: onCreateSubmit not found")
	}
	end := strings.Index(pane[start:], "\n    }\n")
	if end < 0 {
		t.Fatal("pane-board.tmpl: the end of onCreateSubmit not found")
	}
	h := pane[start : start+end]
	for _, want := range []string{
		"trimName(subjectEl.value)",
		"subjectProblem(subject)",
		"await serverErrorText(r)",
		"msgEl.textContent = subjectWhy",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("onCreateSubmit lacks %s", want)
		}
	}
	if strings.Index(h, "subjectProblem(subject)") > strings.Index(h, "fetch('/api/board/threads'") {
		t.Error("the subject must be checked before the request is sent")
	}
	if strings.Contains(h, "subjectEl.value.trim()") {
		t.Error("the subject must be trimmed with trimName, not String.prototype.trim (it keeps U+0085, strips U+FEFF)")
	}
	for _, bad := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write"} {
		if strings.Contains(h, bad) {
			t.Errorf("onCreateSubmit contains %q: the server's sentence and the pre-check's must stay text", bad)
		}
	}
	// One definition of the class: the board declares neither its own regexp nor its own copy.
	if strings.Contains(pane, `\p{Cc}`) || strings.Contains(pane, "hasHiddenChar =") {
		t.Error("pane-board.tmpl restates the Cc/Cf class; use hasHiddenChar from core-util.tmpl")
	}
}
