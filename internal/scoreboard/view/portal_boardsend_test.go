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
//     textContent), and the generic fallback only when the response has none.
func TestBoardReplyPaths_TrimLikeTheServerAndShowTheServerSentence(t *testing.T) {
	parts := portalPartials(t)
	util, pane := partialBody(parts, "core-util.tmpl"), partialBody(parts, "pane-board.tmpl")
	var rules strings.Builder
	for _, c := range []string{"trimName", "serverErrorText"} {
		rules.WriteString(extractJSConst(t, util, c) + "\n")
	}
	rules.WriteString(extractJSConst(t, pane, "MAX_BODY_BYTES") + "\n")
	rules.WriteString(extractJSFunc(t, pane, "bodyByteLen") + "\n")
	rules.WriteString(boardHandlerJS(t, "onAppendSubmit") + "\n")
	rules.WriteString(boardHandlerJS(t, "onReplySubmit") + "\n")
	driver := `
var TextEncoder = function () { this.encode = function (s) { var n = 0; for (var ch of s) { var c = ch.codePointAt(0); n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4; } return { length: n }; }; };
var busy = false, selectedTid = 't1', rendered = [], calls = [], mode = 'ok', els = {};
function renderThread(d) { rendered.push(d); }
var document = { getElementById: function (id) { return els[id]; } };
var fetch = function (url, opts) {
  calls.push({ url: url, body: JSON.parse(opts.body) });
  if (mode === 'bad') return Promise.resolve({ status: 400, ok: false, json: function () { return Promise.resolve({ error: '<img src=x onerror=alert(1)>' }); } });
  if (mode === 'nobody') return Promise.resolve({ status: 502, ok: false, json: function () { return Promise.reject(new Error('not json')); } });
  return Promise.resolve({ status: 200, ok: true, json: function () { return Promise.resolve({ id: 't1' }); } });
};
var paths = {
  append: { fn: onAppendSubmit, body: 'board-append-body', msg: 'board-append-msg' },
  admin:  { fn: onReplySubmit,  body: 'board-admin-reply-body', msg: 'board-admin-reply-msg' },
};
function run(which, body, m) {
  var p = paths[which];
  mode = m || 'ok'; calls.length = 0; rendered.length = 0;
  els[p.body] = { value: body };
  els[p.msg] = { textContent: '', className: '' };
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
    .then(function () { return run(w, 'hello', 'nobody'); }).then(function (r) { out[w + '.nobody'] = r; });
});
`
	type result struct {
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
	var got map[string]result
	runJS(t, rules.String(), driver, nil, &got)
	for _, w := range []struct{ name, url string }{
		{"append", "/api/board/threads/t1/messages"},
		{"admin", "/api/admin/board/threads/t1/reply"},
	} {
		t.Run(w.name, func(t *testing.T) {
			for _, k := range []string{"nel", "bom", "zwj", "empty", "bad", "nobody"} {
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
		})
	}
}
