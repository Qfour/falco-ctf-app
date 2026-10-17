package view

import (
	"strings"
	"testing"
)

// The board's two reply paths (a participant's append to a thread: onAppendSubmit, the
// operator's reply: onReplySubmit) RUN in goja the way TestSubjectForm_RunsThePrecheckBeforeTheRequest
// runs the new-thread path (app#415, a follow-up of app#411 / app#420):
//
//   - the body is trimmed with trimName (the server's trim set), not String.prototype.trim:
//     a trailing U+0085 is stripped (the server strips it), a leading U+FEFF is kept (the
//     server keeps it; trim() would strip it, a different length / emptiness verdict);
//   - a body is a block, so there is NO Cc / Cf pre-check on it (unlike the subject, an
//     inline string): a ZWJ and a line break go to the server, which decides;
//   - a failed response shows the server's own sentence as TEXT (serverErrorText ->
//     textContent), and the generic fallback only when the response has none;
//   - a sent message leaves no refusal of an earlier attempt on screen.
//
// What this does NOT prove: the document and fetch here are FAKES (a Response with a
// one-shot json(), a getElementById that returns plain objects). The CSP, a real event
// loop (the poll interleaving with a send), dialogs and the DOM are the e2e harness's
// (ADR-0031); a fake handler test shows the handler's own logic, not the page.

// boardSendResult is what the driver reports after one run of a handler.
type boardSendResult struct {
	Calls []struct {
		URL  string            `json:"url"`
		Body map[string]string `json:"body"`
	} `json:"calls"`
	Msg      string `json:"msg"`
	Cls      string `json:"cls"`
	Rendered int    `json:"rendered"`
	Busy     bool   `json:"busy"`
	Left     string `json:"left"`
}

// runBoardSend runs the two handlers' source (appendJS, replyJS: the real text, or a
// mutation of it) through the scenarios and returns "<append|admin>.<scenario>" -> result.
func runBoardSend(t *testing.T, appendJS, replyJS string) map[string]boardSendResult {
	t.Helper()
	parts := portalPartials(t)
	util, pane := partialBody(parts, "core-util.tmpl"), partialBody(parts, "pane-board.tmpl")
	var rules strings.Builder
	for _, c := range []string{"trimName", "serverErrorText"} {
		rules.WriteString(extractJSConst(t, util, c) + "\n")
	}
	rules.WriteString(extractJSConst(t, pane, "MAX_BODY_BYTES") + "\n")
	rules.WriteString(extractJSFunc(t, pane, "bodyByteLen") + "\n")
	rules.WriteString(appendJS + "\n" + replyJS + "\n")
	driver := `
var TextEncoder = function () { this.encode = function (s) { var n = 0; for (var ch of s) { var c = ch.codePointAt(0); n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4; } return { length: n }; }; };
var busy = false, selectedTid = 't1', rendered = [], calls = [], mode = 'ok', els = {};
function renderThread(d) { rendered.push(d); }
var document = { getElementById: function (id) { return els[id]; } };
// A Response body is ONE-SHOT, as in Fetch: a second json() rejects (bodyUsed). A handler
// that reads the body before the status check leaves serverErrorText with nothing to read.
function resp(status, ok, parse) {
  var bodyUsed = false;
  return { status: status, ok: ok, get bodyUsed() { return bodyUsed; }, json: function () {
    if (bodyUsed) return Promise.reject(new TypeError('Body has already been consumed.'));
    bodyUsed = true; return parse();
  } };
}
var fetch = function (url, opts) {
  calls.push({ url: url, body: JSON.parse(opts.body) });
  if (mode === 'bad') return Promise.resolve(resp(400, false, function () { return Promise.resolve({ error: '<img src=x onerror=alert(1)>' }); }));
  if (mode === 'nobody') return Promise.resolve(resp(502, false, function () { return Promise.reject(new Error('not json')); }));
  return Promise.resolve(resp(200, true, function () { return Promise.resolve({ id: 't1' }); }));
};
var paths = {
  append: { fn: onAppendSubmit, body: 'board-append-body', msg: 'board-append-msg' },
  admin:  { fn: onReplySubmit,  body: 'board-admin-reply-body', msg: 'board-admin-reply-msg' },
};
// keep: the form is still mounted (the message element is the one the earlier attempt used).
function run(which, body, m, keep) {
  var p = paths[which];
  mode = m || 'ok'; calls.length = 0; rendered.length = 0;
  els[p.body] = { value: body };
  if (!keep) els[p.msg] = { textContent: '', className: 'submit-msg' };
  return p.fn({ preventDefault: function () {} }, 't1').then(function () {
    return { calls: calls.slice(), msg: els[p.msg].textContent, cls: els[p.msg].className, rendered: rendered.length, busy: busy, left: els[p.body].value };
  });
}
var out = {};
var chain = Promise.resolve();
['append', 'admin'].forEach(function (w) {
  chain = chain
    .then(function () { return run(w, '  hello\u0085'); }).then(function (r) { out[w + '.nel'] = r; })
    .then(function () { return run(w, '\uFEFFhello'); }).then(function (r) { out[w + '.bom'] = r; })
    .then(function () { return run(w, 'a\u200D\nb'); }).then(function (r) { out[w + '.zwj'] = r; })
    .then(function () { return run(w, ' \u0085 \u3000'); }).then(function (r) { out[w + '.empty'] = r; })
    .then(function () { return run(w, 'hello', 'bad'); }).then(function (r) { out[w + '.bad'] = r; })
    .then(function () { return run(w, 'hello', 'nobody'); }).then(function (r) { out[w + '.nobody'] = r; })
    .then(function () { return run(w, 'hello', 'bad'); })
    .then(function () { return run(w, 'hello', 'ok', true); }).then(function (r) { out[w + '.recovered'] = r; });
});
`
	var got map[string]boardSendResult
	runJS(t, rules.String(), driver, nil, &got)
	return got
}

func TestBoardReplyPaths_TrimLikeTheServerAndShowTheServerSentence(t *testing.T) {
	got := runBoardSend(t, boardHandlerJS(t, "onAppendSubmit"), boardHandlerJS(t, "onReplySubmit"))
	for _, w := range []struct{ name, url string }{
		{"append", "/api/board/threads/t1/messages"},
		{"admin", "/api/admin/board/threads/t1/reply"},
	} {
		t.Run(w.name, func(t *testing.T) {
			for _, k := range []string{"nel", "bom", "zwj", "empty", "bad", "nobody", "recovered"} {
				if _, ok := got[w.name+"."+k]; !ok {
					t.Fatalf("%s: the scenario did not finish", k)
				}
			}
			sent := func(k string) (string, bool) {
				r := got[w.name+"."+k]
				if len(r.Calls) != 1 || r.Calls[0].URL != w.url {
					return "", false
				}
				return r.Calls[0].Body["body"], true
			}
			if b, ok := sent("nel"); !ok || b != "hello" {
				t.Errorf("a trailing NEL must be trimmed like the server does (trimName), sent %q (sent once: %v)", b, ok)
			}
			if b, ok := sent("bom"); !ok || b != "\uFEFFhello" {
				t.Errorf("a leading U+FEFF must be kept (the server keeps it; String.prototype.trim would strip it), sent %q (sent once: %v)", b, ok)
			}
			if b, ok := sent("zwj"); !ok || b != "a\u200D\nb" {
				t.Errorf("a ZWJ and a line break in a body go to the server untouched (no Cc/Cf pre-check on a block), sent %q (sent once: %v)", b, ok)
			}
			if e := got[w.name+".empty"]; len(e.Calls) != 0 || e.Msg == "" || !strings.Contains(e.Cls, "err") {
				t.Errorf("a body that is only server-whitespace sends nothing and says why: %+v", e)
			}
			if b := got[w.name+".bad"]; len(b.Calls) != 1 || b.Msg != "<img src=x onerror=alert(1)>" || !strings.Contains(b.Cls, "err") || b.Busy || b.Rendered != 0 || b.Left != "hello" {
				t.Errorf("a 400 must show the server's sentence as text, keep the draft, release busy: %+v", b)
			}
			if n := got[w.name+".nobody"]; n.Msg != "Could not send (HTTP 502)." || !strings.Contains(n.Cls, "err") || n.Busy {
				t.Errorf("a failure without a JSON body falls back to the generic sentence: %+v", n)
			}
			if ok := got[w.name+".nel"]; ok.Rendered != 1 || ok.Busy || ok.Left != "" {
				t.Errorf("a sent body clears the textarea and shows the thread: %+v", ok)
			}
			if r := got[w.name+".recovered"]; len(r.Calls) != 1 || r.Msg != "" || r.Cls != "submit-msg" {
				t.Errorf("a send after a refusal must clear the refusal (text and err class): %+v", r)
			}
		})
	}
}

// TestBoardReplyPaths_MockCatchesTheBodyReadBeforeTheStatusCheck: the fake Response is
// one-shot like Fetch's, so a handler that reads r.json() BEFORE `if (!r.ok)` (the shape
// this PR removed) leaves serverErrorText nothing: the server's sentence is lost and the
// 'bad' scenario goes red. The mutation is applied to the real source of each handler.
func TestBoardReplyPaths_MockCatchesTheBodyReadBeforeTheStatusCheck(t *testing.T) {
	mutate := func(js string) string {
		const gate = "if (!r.ok) {"
		if strings.Count(js, gate) != 1 {
			t.Fatalf("want exactly one %q in the handler to mutate", gate)
		}
		return strings.Replace(js, gate, "await r.json().catch(() => ({}));\n        "+gate, 1)
	}
	appendJS, replyJS := boardHandlerJS(t, "onAppendSubmit"), boardHandlerJS(t, "onReplySubmit")
	got := runBoardSend(t, mutate(appendJS), mutate(replyJS))
	for _, w := range []string{"append", "admin"} {
		if b := got[w+".bad"]; b.Msg == "<img src=x onerror=alert(1)>" {
			t.Errorf("%s: the mutated handler (body read before the status check) still shows the server's sentence: the mock does not enforce one read", w)
		}
	}
}
