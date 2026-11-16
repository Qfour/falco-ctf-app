package view

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

// V40 (ADR-0056 A6): the participant portal's answer form for an investigate mission
// (answerSection / answerRowHTML / answerOutcome / onAnswerSubmit and the repaint
// helpers in pane-story.tmpl), RUN in goja the way the Profile form and the board's reply
// paths are (portal_nameproblem_test.go, portal_boardsend_test.go, ADR-0035): the functions
// are cut out of the SOURCE partial and run against a fake document and a fake fetch.
// There is no investigate mission in the repo yet, so the journey detail below is
// synthetic (the shape of MissionDetail.questions in docs/openapi-scoreboard.yaml).
//
// What this does NOT prove: the document, fetch and focus are FAKES (a getElementById that
// returns plain objects, a one-shot Response). The CSP, the real poll interleaving with a
// submit, the layout, and that a browser keeps a caret are the e2e harness's (ADR-0031).

// cutStoryBlock cuts a function out of pane-story.tmpl by its declaration header (for the
// forms extractJSFunc cannot find: `async function name(`), up to the closing brace at
// two-space indent, and requires that the cut hold exactly one declaration.
func cutStoryBlock(t *testing.T, src, header string) string {
	t.Helper()
	start := strings.Index(src, "\n  "+header)
	if start < 0 {
		t.Fatalf("%q not found in pane-story.tmpl (the test cuts it out of the source)", header)
	}
	rest := src[start+1:]
	end := strings.Index(rest, "\n  }\n")
	if end < 0 {
		t.Fatalf("%q has no closing brace at 2-space indent", header)
	}
	blk := rest[:end+len("\n  }")]
	if n := strings.Count(blk, "function "); n != 1 {
		t.Fatalf("the text cut out for %q holds %d `function ` declarations, want exactly 1:\n%s", header, n, blk)
	}
	return blk
}

// answerRules is the real source of everything the answer form runs on: esc (core-util),
// the two state maps and the functions (pane-story), renderDetail with what it calls (the
// "no questions: the page is what it was" check needs the whole detail painter).
func answerRules(t *testing.T, story string) string {
	t.Helper()
	util := partialBody(portalPartials(t), "core-util.tmpl")
	var b strings.Builder
	b.WriteString(extractJSConst(t, util, "esc") + "\n")
	for _, c := range []string{"answerDrafts", "answerMsgs"} {
		b.WriteString(extractJSConst(t, story, c) + "\n")
	}
	for _, f := range []string{
		"slugify", "answerKey", "answerFormatHint", "answerRowState", "answerRowHTML", "answerSection",
		"answerOutcome", "pruneAnswerState", "captureAnswerFocus", "restoreAnswerFocus",
		"kickerFor", "backToCurrentHTML", "hintJumpsHTML", "renderDetail", "renderFalcoRule",
		"triggerSection", "evalPending", "evadeSection", "dirtySection", "autoSolveStatus", "submitForm",
	} {
		b.WriteString(extractJSFunc(t, story, f) + "\n")
	}
	b.WriteString(cutStoryBlock(t, story, "async function onAnswerSubmit(") + "\n")
	// wireDetail's body mentions the word "function" in a comment, so it is cut by funcBody.
	b.WriteString(funcBody(t, story, "wireDetail") + "\n")
	return b.String()
}

const answerDriver = oneShotResponseJS + `
var user = 'u1', busy = false, refreshCalls = 0, announced = [], fetchCalls = [], fetchMode = 'ok';
var announce = function (m) { announced.push(m); };
var refresh = async function () { refreshCalls++; };
var els = {};
var document = { activeElement: null, getElementById: function (id) { return els[id] || null; } };
function q(over) { var b = { id: 'q1', prompt: 'P', format: 'path', attempts: 5, remaining: 3, correct: false }; for (var k in over) b[k] = over[k]; return b; }
function section(qs, status) { return answerSection({ id: 'c1', status: status || 'current', questions: qs }); }
function offs(html, name) { return (html.match(new RegExp('<' + name + '[^>]*>', 'g')) || []).map(function (t) { return / disabled(\s|>|=)/.test(t); }); }
function states(qs, status) { var h = section(qs, status); return { input: offs(h, 'input'), btn: offs(h, 'button'), html: h }; }
function clearState() {
  Object.keys(answerDrafts).forEach(function (k) { delete answerDrafts[k]; });
  Object.keys(answerMsgs).forEach(function (k) { delete answerMsgs[k]; });
}
function R(status, correct, solved, remaining) { return { status: status, correct: correct, solved: solved, remaining: remaining }; }
var out = {};

// Escaping: the prompt (operator text), the format value, the typed draft and the result line.
var nasty = '<b>"x"</b> & \'y\'';
out.escBad = section([q({ prompt: nasty, format: '"><img src=x onerror=alert(1)>' })]);
answerDrafts['c1/q1'] = '"><script>alert(1)</script>';
answerMsgs['c1/q1'] = { cls: 'err', text: '<i>boom</i>' };
out.esc = section([q({ prompt: nasty })]);
clearState();

// States.
out.states = {
  open: states([q({})]),
  retry: states([q({ correct: true, remaining: 0 })]),
  exhausted: states([q({ remaining: 0 })]),
  solved: states([q({ correct: true })], 'solved'),
  multi: states([q({ id: 'q1', correct: true }), q({ id: 'q2', remaining: 0 }), q({ id: 'q3' })]),
  seven: states([q({ remaining: 7, attempts: 10 })]),
  locked: states([q({})], 'locked'),
};
out.empty = section([]);
out.absent = answerSection({ id: 'c1', status: 'current' });
out.nullq = answerSection({ id: 'c1', status: 'current', questions: null });

// Outcomes: only the HTTP status and the four fields decide.
out.outcomes = {
  correctSolved: answerOutcome(200, R('correct', true, true, 4)),
  correctOpen: answerOutcome(200, R('correct', true, false, 4)),
  incorrect2: answerOutcome(200, R('incorrect', false, false, 2)),
  incorrect4: answerOutcome(200, R('incorrect', false, false, 4)),
  exhausted: answerOutcome(200, R('exhausted', false, false, 0)),
  alreadyOpen: answerOutcome(200, R('already-correct', true, false, 4)),
  alreadySolved: answerOutcome(200, R('already-correct', true, true, 4)),
  bogus: answerOutcome(200, R('bogus', true, true, 4)),
  nullBody: answerOutcome(200, null),
  noRemaining: answerOutcome(200, { status: 'correct', correct: true, solved: true }),
  s0: answerOutcome(0, null),
  s400: answerOutcome(400, null),
  s403: answerOutcome(403, null),
  s404: answerOutcome(404, null),
  s429: answerOutcome(429, null),
  s500: answerOutcome(500, null),
  s502: answerOutcome(502, null),
};

// A repaint after an attempt was spent: the typed text and the last result line come back.
answerDrafts['c1/q1'] = 'typed "text"';
answerMsgs['c1/q1'] = { cls: 'err', text: 'earlier result' };
out.rerender = section([q({ remaining: 2 })]);
clearState();

// Focus: read before the repaint, given back after it.
var focused = [], caret = null;
document.activeElement = { id: 'pane-journey-answer-input-0', selectionStart: 2, selectionEnd: 4 };
var cap = captureAnswerFocus();
els = { 'pane-journey-answer-input-0': { disabled: false, focus: function () { focused.push('input'); }, setSelectionRange: function (a, b) { caret = [a, b]; } } };
restoreAnswerFocus(cap);
out.focus = { cap: cap, focused: focused.slice(), caret: caret };
focused.length = 0;
els = { 'pane-journey-answer-input-0': { disabled: true, focus: function () { focused.push('disabled'); } } };
restoreAnswerFocus(cap);
out.focusDisabled = focused.slice();
els = {};
restoreAnswerFocus(cap);
restoreAnswerFocus(null);
document.activeElement = { id: 'pane-journey-flag-input', selectionStart: 0, selectionEnd: 0 };
out.focusOther = captureAnswerFocus();
document.activeElement = null;
out.focusNone = captureAnswerFocus();

// Another mission's drafts and result lines are dropped before the paint.
answerDrafts['c1/q1'] = 'a'; answerDrafts['c2/q1'] = 'b'; answerDrafts['c10/q1'] = 'c';
answerMsgs['c1/q1'] = { cls: 'ok', text: 't' }; answerMsgs['c2/q9'] = { cls: 'ok', text: 't' };
pruneAnswerState({ id: 'c1' });
out.prune = { drafts: Object.keys(answerDrafts), msgs: Object.keys(answerMsgs) };
pruneAnswerState(null);
out.pruneAll = { drafts: Object.keys(answerDrafts), msgs: Object.keys(answerMsgs) };

// No questions: the detail is what it was.
var det = { id: '20-inv', title: 'T', type: 'investigate', status: 'current', hasJourney: true, steps: [], hints: { total: 0, opened: [], lockedCount: 0, nextIndex: 0, penalty: 0 } };
out.detail = {
  none: renderDetail(det),
  empty: renderDetail(Object.assign({}, det, { questions: [] })),
  withQ: renderDetail(Object.assign({}, det, { questions: [q({})] })),
  evadeNone: renderDetail(Object.assign({}, det, { type: 'evade' })),
  evadeEmpty: renderDetail(Object.assign({}, det, { type: 'evade', questions: [] })),
  evadeLocked: renderDetail(Object.assign({}, det, { type: 'evade', status: 'locked' })),
};

// The write path.
var replies = {
  incorrect: [200, R('incorrect', false, false, 2)],
  correctOpen: [200, R('correct', true, false, 4)],
  correctSolved: [200, R('correct', true, true, 4)],
  alreadyOpen: [200, R('already-correct', true, false, 4)],
  exhausted: [200, R('exhausted', false, false, 0)],
  e400: [400, { error: '<img src=x onerror=alert(1)>' }],
  e403: [403, { error: '<img src=x onerror=alert(1)>' }],
  e404: [404, { error: '<img src=x onerror=alert(1)>' }],
  e429: [429, { error: '<img src=x onerror=alert(1)>' }],
  e500: [500, { error: '<img src=x onerror=alert(1)>' }],
  e502: [502, { error: '<img src=x onerror=alert(1)>' }],
};
var fetch = function (url, opts) {
  fetchCalls.push({ url: url, method: opts.method, ct: opts.headers['Content-Type'], body: JSON.parse(opts.body) });
  if (fetchMode === 'down') return Promise.reject(new TypeError('Failed to fetch'));
  var e = replies[fetchMode];
  return Promise.resolve(resp(e[0], e[0] === 200, function () { return Promise.resolve(e[1]); }));
};
async function run(mode, value) {
  var input = { value: value, disabled: false }, btn = { disabled: false }, msg = { className: 'submit-msg', textContent: '' };
  els = { 'pane-journey-answer-input-0': input, 'pane-journey-answer-btn-0': btn, 'pane-journey-answer-msg-0': msg };
  fetchMode = mode; fetchCalls.length = 0; refreshCalls = 0; announced.length = 0;
  answerDrafts['c1/q1'] = '/typed';
  var ev = { prevented: false, preventDefault: function () { this.prevented = true; } };
  await onAnswerSubmit(ev, 'c1', q({}), 0);
  return { calls: fetchCalls.slice(), msg: msg.textContent, cls: msg.className, inputDisabled: input.disabled, btnDisabled: btn.disabled, busy: busy, refreshes: refreshCalls, announced: announced.slice(), prevented: ev.prevented, draftKept: answerDrafts['c1/q1'] === '/typed' };
}
async function main() {
  out.sub = {};
  out.sub.empty = await run('incorrect', '   ');
  for (var m of Object.keys(replies)) { out.sub[m] = await run(m, '  /etc/x  '); }
  out.sub.down = await run('down', '/x');
  busy = true;
  out.sub.busy = await run('incorrect', '/x');
  busy = false;

  // wireDetail's question part, RUN: a fake form / input that record their listeners.
  clearState();
  els = {};
  document.querySelectorAll = function () { return []; };
  function elWith(id) { var e = { id: id, value: '', disabled: false, className: '', textContent: '', l: {}, addEventListener: function (t, f) { this.l[t] = f; } }; els[id] = e; return e; }
  els['pane-story'] = { querySelectorAll: function () { return []; } };
  var f = elWith('pane-journey-answer-form-0'), inp = elWith('pane-journey-answer-input-0');
  elWith('pane-journey-answer-btn-0'); elWith('pane-journey-answer-msg-0');
  wireDetail({ id: 'c1', hints: { opened: [] }, questions: [q({})] });
  inp.value = 'half-typed';
  inp.l.input();
  var draftAfterInput = answerDrafts['c1/q1'];
  inp.value = '/etc/x';
  fetchMode = 'incorrect'; fetchCalls.length = 0; refreshCalls = 0;
  await f.l.submit({ preventDefault: function () {} });
  out.wire = { hasSubmit: typeof f.l.submit === 'function', hasInput: typeof inp.l.input === 'function', draft: draftAfterInput, calls: fetchCalls.length, refreshes: refreshCalls };

  // The repaint sequence render() runs, with the real helpers: prune, read the focus, paint, give it back.
  clearState();
  answerDrafts['c1/q1'] = 'keep me';
  document.activeElement = { id: 'pane-journey-answer-input-0', selectionStart: 3, selectionEnd: 3 };
  pruneAnswerState({ id: 'c1' });
  var saved = captureAnswerFocus();
  var htmlSame = section([q({ remaining: 2 })]);
  var fresh = { disabled: false, focus: function () { this.got = true; }, setSelectionRange: function (a, b) { this.caret = [a, b]; } };
  els = { 'pane-journey-answer-input-0': fresh };
  restoreAnswerFocus(saved);
  pruneAnswerState({ id: 'c2' });
  var htmlOther = answerSection({ id: 'c2', status: 'current', questions: [q({})] });
  out.through = { htmlSame: htmlSame, focused: fresh.got === true, caret: fresh.caret || null, htmlOther: htmlOther };
}
main();
`

type answerStateJS struct {
	Input []bool `json:"input"`
	Btn   []bool `json:"btn"`
	HTML  string `json:"html"`
}

type answerOutcomeJS struct {
	Cls     string `json:"cls"`
	Text    string `json:"text"`
	Changed bool   `json:"changed"`
	Lock    bool   `json:"lock"`
}

type answerSubmitJS struct {
	Calls []struct {
		URL    string            `json:"url"`
		Method string            `json:"method"`
		CT     string            `json:"ct"`
		Body   map[string]string `json:"body"`
	} `json:"calls"`
	Msg           string   `json:"msg"`
	Cls           string   `json:"cls"`
	InputDisabled bool     `json:"inputDisabled"`
	BtnDisabled   bool     `json:"btnDisabled"`
	Busy          bool     `json:"busy"`
	Refreshes     int      `json:"refreshes"`
	Announced     []string `json:"announced"`
	Prevented     bool     `json:"prevented"`
	DraftKept     bool     `json:"draftKept"`
}

type answerKeysJS struct {
	Drafts []string `json:"drafts"`
	Msgs   []string `json:"msgs"`
}

type answerFocusJS struct {
	ID    string `json:"id"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type answerFocusRunJS struct {
	Cap     *answerFocusJS `json:"cap"`
	Focused []string       `json:"focused"`
	Caret   []int          `json:"caret"`
}

type answerDriverOut struct {
	EscBad        string                     `json:"escBad"`
	Esc           string                     `json:"esc"`
	States        map[string]answerStateJS   `json:"states"`
	Empty         string                     `json:"empty"`
	Absent        string                     `json:"absent"`
	NullQ         string                     `json:"nullq"`
	Outcomes      map[string]answerOutcomeJS `json:"outcomes"`
	Rerender      string                     `json:"rerender"`
	Focus         answerFocusRunJS           `json:"focus"`
	FocusDisabled []string                   `json:"focusDisabled"`
	FocusOther    *answerFocusJS             `json:"focusOther"`
	FocusNone     *answerFocusJS             `json:"focusNone"`
	Prune         answerKeysJS               `json:"prune"`
	PruneAll      answerKeysJS               `json:"pruneAll"`
	Detail        map[string]string          `json:"detail"`
	Sub           map[string]answerSubmitJS  `json:"sub"`
	Wire          answerWireJS               `json:"wire"`
	Through       answerThroughJS            `json:"through"`
}

type answerWireJS struct {
	HasSubmit bool   `json:"hasSubmit"`
	HasInput  bool   `json:"hasInput"`
	Draft     string `json:"draft"`
	Calls     int    `json:"calls"`
	Refreshes int    `json:"refreshes"`
}

type answerThroughJS struct {
	HTMLSame  string `json:"htmlSame"`
	Focused   bool   `json:"focused"`
	Caret     []int  `json:"caret"`
	HTMLOther string `json:"htmlOther"`
}

type journeyPollJS struct {
	Rendered int    `json:"rendered"`
	Updated  string `json:"updated"`
}

func runAnswerDriver(t *testing.T, story string) answerDriverOut {
	t.Helper()
	var got answerDriverOut
	runJS(t, answerRules(t, story), answerDriver, nil, &got)
	return got
}

func answerStory(t *testing.T) string {
	t.Helper()
	return partialBody(portalPartials(t), "pane-story.tmpl")
}

func TestPortalAnswer_EveryValueIsEscaped(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	// In order: the prompt (all five special characters), the typed draft put back into
	// value="", the result line.
	for _, want := range []string{
		`&lt;b&gt;&quot;x&quot;&lt;/b&gt; &amp; &#39;y&#39;`,
		`&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`,
		`&lt;i&gt;boom&lt;/i&gt;`,
	} {
		if !strings.Contains(got.Esc, want) {
			t.Errorf("the answer form's markup lacks the escaped %q:\n%s", want, got.Esc)
		}
	}
	for _, raw := range []string{"<b>", "</b>", "<script", "<i>"} {
		if strings.Contains(got.Esc, raw) {
			t.Errorf("the answer form's markup holds the raw %q (a prompt / draft / result line reached the page unescaped):\n%s", raw, got.Esc)
		}
	}
	if strings.Contains(got.EscBad, "<img") {
		t.Errorf("a format value with markup reached the page raw: %s", got.EscBad)
	}
}

// TestPortalAnswer_MockCatchesAnUnescapedPrompt: the escape check above must be able to
// fail. The mutation is applied to the real source.
func TestPortalAnswer_MockCatchesAnUnescapedPrompt(t *testing.T) {
	story := answerStory(t)
	if strings.Count(story, "esc(q.prompt)") != 1 {
		t.Fatal("want exactly one esc(q.prompt) in pane-story.tmpl to mutate")
	}
	got := runAnswerDriver(t, strings.Replace(story, "esc(q.prompt)", "q.prompt", 1))
	if !strings.Contains(got.Esc, "<b>") {
		t.Error("the mutated source (prompt not escaped) still passes the escape check: the driver does not see the raw prompt")
	}
}

func TestPortalAnswer_FieldStatesAndRemaining(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	st := got.States
	both := func(name string, in, btn bool) {
		s := st[name]
		if len(s.Input) != 1 || len(s.Btn) != 1 || s.Input[0] != in || s.Btn[0] != btn {
			t.Errorf("%s: input disabled / button disabled = %v / %v, want %v / %v", name, s.Input, s.Btn, in, btn)
		}
	}
	both("open", false, false)
	// ADR-0056 D5 step 5: answered but the mission is not solved: the field STAYS enabled
	// (a resubmission completes a solve whose write failed), even with no attempts left.
	both("retry", false, false)
	both("exhausted", true, true)
	both("solved", true, true)
	m := st["multi"]
	if len(m.Input) != 3 || m.Input[0] || !m.Input[1] || m.Input[2] || len(m.Btn) != 3 || m.Btn[0] || !m.Btn[1] || m.Btn[2] {
		t.Errorf("multi: want [answered-unsolved enabled, exhausted disabled, open enabled], got input %v button %v", m.Input, m.Btn)
	}
	if !strings.Contains(m.HTML, "1 / 3 問 正解") {
		t.Errorf("multi: the heading should count answered questions: %s", m.HTML)
	}
	if !strings.Contains(st["solved"].HTML, "クリア済み") {
		t.Errorf("solved: the section should say the mission is cleared: %s", st["solved"].HTML)
	}
	// remaining is shown as the journey sent it.
	if h := st["open"].HTML; !strings.Contains(h, "残り 3 回 / 全 5 回") {
		t.Errorf("open: remaining 3 of 5 not shown as given: %s", h)
	}
	if h := st["seven"].HTML; !strings.Contains(h, "残り 7 回 / 全 10 回") {
		t.Errorf("seven: remaining 7 of 10 not shown as given: %s", h)
	}
	if h := st["exhausted"].HTML; !strings.Contains(h, "回数を使い切りました") {
		t.Errorf("exhausted: should say the attempts are used up: %s", h)
	}
	// The format hint is the portal's own words for a known format, nothing for an unknown one.
	if !strings.Contains(st["open"].HTML, "絶対パス") {
		t.Errorf("open: the path format's hint is missing: %s", st["open"].HTML)
	}
}

func TestPortalAnswer_OutcomesComeFromTheStatusAndTheFourFields(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	o := got.Outcomes
	// Every outcome reads differently, except the three malformed 200s, which share the one
	// "could not read the response" sentence.
	seen := map[string]string{}
	for k, v := range o {
		if v.Text == "" {
			t.Errorf("%s: no sentence", k)
		}
		if k == "bogus" || k == "nullBody" || k == "noRemaining" {
			continue
		}
		if prev, dup := seen[v.Text]; dup {
			t.Errorf("%s and %s show the same sentence %q (each outcome must read differently)", k, prev, v.Text)
		}
		seen[v.Text] = k
	}
	type want struct {
		cls     string
		lock    bool
		changed bool
		has     string
	}
	for name, w := range map[string]want{
		"correctSolved": {"ok", true, true, "ミッションクリア"},
		"correctOpen":   {"ok", false, true, "残りの設問"},
		"incorrect2":    {"err", false, true, "残り 2 回"},
		"incorrect4":    {"err", false, true, "残り 4 回"}, // the response's number, not "the last one minus one"
		"exhausted":     {"err", true, true, "使い切りました"},
		"alreadyOpen":   {"ok", false, true, "すでに正解済み"},
		"alreadySolved": {"ok", true, true, "クリア済み"},
		"bogus":         {"warn", false, true, "解釈できません"},
		"nullBody":      {"warn", false, true, "解釈できません"},
		"noRemaining":   {"warn", false, true, "解釈できません"},
		"s0":            {"err", false, false, "通信エラー"},
		"s400":          {"err", false, false, "形式"},
		"s403":          {"err", false, false, "許可されていません"},
		"s404":          {"err", false, false, "見つかりません"},
		"s429":          {"warn", false, false, "待ってから"},
		"s500":          {"err", false, true, "採点できませんでした"},
		"s502":          {"err", false, false, "HTTP 502"},
	} {
		g := o[name]
		if g.Cls != w.cls || g.Lock != w.lock || g.Changed != w.changed || !strings.Contains(g.Text, w.has) {
			t.Errorf("%s: got %+v, want cls %q lock %v changed %v containing %q", name, g, w.cls, w.lock, w.changed, w.has)
		}
	}
	// 400 says the count did not move; 500 must not claim that (a failure after the attempt
	// was counted leaves it spent, ADR-0056 D5).
	if !strings.Contains(o["s400"].Text, "回数は減っていません") {
		t.Errorf("a 400 must say no attempt was spent: %q", o["s400"].Text)
	}
	if strings.Contains(o["s500"].Text, "減っていません") {
		t.Errorf("a 500 must not claim the count is intact: %q", o["s500"].Text)
	}
}

func TestPortalAnswer_SubmitPath(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	sub := got.Sub
	const wantURL = "/api/users/u1/challenges/c1/questions/q1/answer"
	for _, k := range []string{"empty", "incorrect", "correctOpen", "correctSolved", "alreadyOpen", "exhausted", "e400", "e403", "e404", "e429", "e500", "e502", "down", "busy"} {
		if _, ok := sub[k]; !ok {
			t.Fatalf("%s: the scenario did not finish", k)
		}
	}
	inc := sub["incorrect"]
	if len(inc.Calls) != 1 || inc.Calls[0].URL != wantURL || inc.Calls[0].Method != "POST" || inc.Calls[0].CT != "application/json" || inc.Calls[0].Body["answer"] != "/etc/x" || len(inc.Calls[0].Body) != 1 {
		t.Errorf("one JSON POST of {answer: <trimmed>} to the answer route, got %+v", inc.Calls)
	}
	if !inc.Prevented || inc.Busy || inc.Refreshes != 1 || inc.InputDisabled || inc.BtnDisabled || !inc.DraftKept {
		t.Errorf("a wrong answer: prevents the form post, releases busy, repaints once, leaves the field usable and the draft in place: %+v", inc)
	}
	if !strings.Contains(inc.Msg, "残り 2 回") || inc.Cls != "submit-msg err" || len(inc.Announced) != 1 || inc.Announced[0] != inc.Msg {
		t.Errorf("the response's remaining is shown and announced once: %+v", inc)
	}
	if e := sub["empty"]; len(e.Calls) != 0 || !e.Prevented || e.Busy || e.Refreshes != 0 || !strings.Contains(e.Cls, "err") || e.Msg == "" {
		t.Errorf("an empty answer sends nothing and says why: %+v", e)
	}
	if c := sub["correctOpen"]; c.InputDisabled || c.BtnDisabled || c.Refreshes != 1 {
		t.Errorf("a correct answer on a mission that is not solved keeps the field usable: %+v", c)
	}
	if c := sub["correctSolved"]; !c.InputDisabled || !c.BtnDisabled || c.DraftKept || c.Refreshes != 1 {
		t.Errorf("a solving answer locks the field and drops the draft: %+v", c)
	}
	if a := sub["alreadyOpen"]; a.InputDisabled || a.BtnDisabled || a.Busy {
		t.Errorf("already-correct without a solve keeps the re-submission open (ADR-0056 D5 step 5): %+v", a)
	}
	if x := sub["exhausted"]; !x.InputDisabled || !x.BtnDisabled {
		t.Errorf("exhausted locks the field: %+v", x)
	}
	texts := map[string]string{}
	for _, k := range []string{"e400", "e403", "e404", "e429", "e500", "e502", "down"} {
		r := sub[k]
		if r.Msg == "" || strings.Contains(r.Msg, "img") || !strings.Contains(r.Cls, "err") && !strings.Contains(r.Cls, "warn") {
			t.Errorf("%s: the portal's own sentence, never the server's: %+v", k, r)
		}
		if r.Busy || r.BtnDisabled || r.InputDisabled || len(r.Calls) != 1 && k != "down" {
			t.Errorf("%s: busy released, field usable again: %+v", k, r)
		}
		wantRefresh := 0
		if k == "e500" {
			wantRefresh = 1
		}
		if r.Refreshes != wantRefresh {
			t.Errorf("%s: %d repaints, want %d", k, r.Refreshes, wantRefresh)
		}
		if prev, dup := texts[r.Msg]; dup {
			t.Errorf("%s and %s show the same sentence %q", k, prev, r.Msg)
		}
		texts[r.Msg] = k
	}
	if b := sub["busy"]; len(b.Calls) != 0 || !b.Prevented {
		t.Errorf("a submit while another write is in flight sends nothing: %+v", b)
	}
}

func TestPortalAnswer_RepaintKeepsWhatWasTyped(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	if !strings.Contains(got.Rerender, `value="typed &quot;text&quot;"`) || !strings.Contains(got.Rerender, "earlier result") || !strings.Contains(got.Rerender, "submit-msg err") {
		t.Errorf("a repaint puts the typed text and the last result line back: %s", got.Rerender)
	}
	if c := got.Focus.Cap; c == nil || c.ID != "pane-journey-answer-input-0" || c.Start != 2 || c.End != 4 {
		t.Errorf("the focused answer input and its caret are captured: %+v", got.Focus.Cap)
	}
	if len(got.Focus.Focused) != 1 || got.Focus.Focused[0] != "input" || len(got.Focus.Caret) != 2 || got.Focus.Caret[0] != 2 || got.Focus.Caret[1] != 4 {
		t.Errorf("after the repaint the input is focused again with its caret: %+v", got.Focus)
	}
	if len(got.FocusDisabled) != 0 {
		t.Errorf("a control that came back disabled is not focused: %v", got.FocusDisabled)
	}
	if got.FocusOther != nil || got.FocusNone != nil {
		t.Errorf("only the answer controls are captured (the flag input has its own handling): other %+v none %+v", got.FocusOther, got.FocusNone)
	}
	if len(got.Prune.Drafts) != 1 || got.Prune.Drafts[0] != "c1/q1" || len(got.Prune.Msgs) != 1 || got.Prune.Msgs[0] != "c1/q1" {
		t.Errorf("only the painted mission's drafts and result lines stay (c1, not c10 or c2): %+v", got.Prune)
	}
	if len(got.PruneAll.Drafts) != 0 || len(got.PruneAll.Msgs) != 0 {
		t.Errorf("no mission painted: everything goes: %+v", got.PruneAll)
	}
	// The wiring itself: render() prunes before painting and captures / restores around it,
	// and wireDetail connects each question's form to the handler.
	story := answerStory(t)
	render := funcBody(t, story, "render")
	prune, capt, paint, restore := strings.Index(render, "pruneAnswerState("), strings.Index(render, "captureAnswerFocus()"), strings.Index(render, "detailEl.innerHTML = detailHTML"), strings.Index(render, "restoreAnswerFocus(")
	if prune < 0 || capt < 0 || paint < 0 || restore < 0 || !(prune < capt && capt < paint && paint < restore) {
		t.Errorf("render(): want pruneAnswerState < captureAnswerFocus < the paint < restoreAnswerFocus, got %d %d %d %d", prune, capt, paint, restore)
	}
	if wire := funcBody(t, story, "wireDetail"); !strings.Contains(wire, "onAnswerSubmit(e, det.id, q, i)") || !strings.Contains(wire, "answerDrafts[") {
		t.Error("wireDetail must connect each question's form to onAnswerSubmit and keep answerDrafts current")
	}
}

func TestPortalAnswer_NoSectionWithoutQuestions(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	for name, s := range map[string]string{"empty": got.Empty, "absent": got.Absent, "null": got.NullQ} {
		if s != "" {
			t.Errorf("%s questions: the section must be empty, got %q", name, s)
		}
	}
	d := got.Detail
	if d["none"] != d["empty"] || d["evadeNone"] != d["evadeEmpty"] {
		t.Error("a mission with questions [] must paint exactly as one without the key (the page is unchanged for every existing mission)")
	}
	for _, k := range []string{"none", "empty", "evadeNone", "evadeEmpty"} {
		if strings.Contains(d[k], "pane-journey-answer-") || strings.Contains(d[k], "設問") {
			t.Errorf("%s: an answer field was drawn for a mission without questions", k)
		}
	}
	if n := strings.Count(d["withQ"], `id="pane-journey-answer-form-0"`); n != 1 {
		t.Errorf("a mission with a question draws one form, got %d", n)
	}
}

// The journey's own failure (the API answers 500 when it cannot read an investigate
// mission's counts, ADR-0056 D4) must leave what is on screen alone: refresh() throws on a
// non-ok response BEFORE render(), so the answer form stays as painted.
func TestPortalAnswer_JourneyFailureKeepsThePreviousView(t *testing.T) {
	story := answerStory(t)
	driver := oneShotResponseJS + `
var user = 'u1', viewedMission = null, rendered = 0, mode = '500';
var updated = { textContent: '' };
var document = { getElementById: function (id) { return id === 'pane-journey-updated' ? updated : null; } };
function render(d) { rendered++; }
var fetch = function (url) {
  if (mode === '500') return Promise.resolve(resp(500, false, function () { return Promise.resolve({ error: 'x' }); }));
  return Promise.resolve(resp(200, true, function () { return Promise.resolve({ ok: 1 }); }));
};
var out = {};
async function main() {
  await refresh();
  out.failed = { rendered: rendered, updated: updated.textContent };
  mode = '200';
  await refresh();
  out.ok = { rendered: rendered, updated: updated.textContent };
}
main();
`
	var got struct {
		Failed journeyPollJS `json:"failed"`
		OK     journeyPollJS `json:"ok"`
	}
	runJS(t, cutStoryBlock(t, story, "async function refresh("), driver, nil, &got)
	if got.Failed.Rendered != 0 || got.Failed.Updated != "connection error" {
		t.Errorf("a failed journey poll must not repaint (the answer form stays) and says so on the status line: %+v", got.Failed)
	}
	if got.OK.Rendered != 1 || !strings.HasPrefix(got.OK.Updated, "updated ") {
		t.Errorf("the next good poll repaints: %+v", got.OK)
	}
}

// ADR-0027 free browsing / ADR-0056 D18: a mission not yet reached (locked) can be answered,
// the same as the evade flag form (evadeSection has no status gate). Pinned so that a change
// is a decision, not an accident.
func TestPortalAnswer_UnreachedMissionStaysOpen(t *testing.T) {
	got := runAnswerDriver(t, answerStory(t))
	l := got.States["locked"]
	if len(l.Input) != 1 || len(l.Btn) != 1 || l.Input[0] || l.Btn[0] {
		t.Errorf("an open question of a locked mission must stay enabled: input %v button %v", l.Input, l.Btn)
	}
	if !strings.Contains(got.Detail["evadeLocked"], `id="pane-journey-flag-input"`) {
		t.Error("the existing evade flag form is expected to be drawn for a locked mission (the precedent this behaviour follows)")
	}
}

// The listeners wireDetail attaches to a question's form and input, RUN: typing updates
// answerDrafts (what a repaint puts back), and a submit reaches onAnswerSubmit.
func TestPortalAnswer_WiringKeepsTheDraftAndSubmits(t *testing.T) {
	w := runAnswerDriver(t, answerStory(t)).Wire
	if !w.HasSubmit || !w.HasInput {
		t.Fatalf("wireDetail did not attach the question's submit / input listeners: %+v", w)
	}
	if w.Draft != "half-typed" {
		t.Errorf("an input event must store the typed text in answerDrafts, got %q", w.Draft)
	}
	if w.Calls != 1 || w.Refreshes != 1 {
		t.Errorf("a submit event must reach onAnswerSubmit (one POST, one repaint): %+v", w)
	}
}

// The repaint sequence of render() (prune, read the focus, paint, give the focus back) with
// the real helpers: the same mission keeps the typed text and the focus, another mission
// starts empty. (That render() calls them in this order is checked in
// TestPortalAnswer_RepaintKeepsWhatWasTyped.)
func TestPortalAnswer_RepaintSequenceKeepsInputAndFocus(t *testing.T) {
	th := runAnswerDriver(t, answerStory(t)).Through
	if !strings.Contains(th.HTMLSame, `value="keep me"`) {
		t.Errorf("the same mission's repaint must carry the typed text: %s", th.HTMLSame)
	}
	if !th.Focused || len(th.Caret) != 2 || th.Caret[0] != 3 || th.Caret[1] != 3 {
		t.Errorf("the focused input is focused again with its caret: %+v", th)
	}
	if strings.Contains(th.HTMLOther, "keep me") || !strings.Contains(th.HTMLOther, `value=""`) {
		t.Errorf("another mission's paint must start empty: %s", th.HTMLOther)
	}
}

// answerFormatHint is a third copy of the closed format list (the spec's
// MissionQuestion.format enum, answerformat.Formats()). A format without a hint, or a hint
// for a format that does not exist, goes red here.
func formatHints(t *testing.T, story string) map[string]string {
	t.Helper()
	var got map[string]string
	runJS(t, extractJSFunc(t, story, "answerFormatHint"), `
var out = {};
for (var i = 0; i < FORMATS.length; i++) { out[FORMATS[i]] = answerFormatHint(FORMATS[i]); }
`, map[string]any{"FORMATS": answerformat.Formats()}, &got)
	return got
}

func TestPortalAnswer_FormatHintCoversTheClosedList(t *testing.T) {
	story := answerStory(t)
	formats := answerformat.Formats()
	if len(formats) == 0 {
		t.Fatal("answerformat.Formats() is empty")
	}
	hints := formatHints(t, story)
	for _, f := range formats {
		if hints[f] == "" {
			t.Errorf("answerFormatHint has no hint for the format %q (a new format must get one)", f)
		}
	}
	known := map[string]bool{}
	for _, f := range formats {
		known[f] = true
	}
	fn := extractJSFunc(t, story, "answerFormatHint")
	for _, m := range regexp.MustCompile(`case '([^']+)':`).FindAllStringSubmatch(fn, -1) {
		if !known[m[1]] {
			t.Errorf("answerFormatHint has a case for %q, which is not in answerformat.Formats()", m[1])
		}
	}
	// The mutation: one case removed from the real source goes red.
	const line = "      case 'sequence': return '設問の指示どおりの順序で';\n"
	if strings.Count(story, line) != 1 {
		t.Fatal("want exactly one sequence case in answerFormatHint to mutate")
	}
	if h := formatHints(t, strings.Replace(story, line, "", 1)); h["sequence"] != "" {
		t.Error("the mutated source (sequence case removed) still returns a hint: the check cannot fail")
	}
}
