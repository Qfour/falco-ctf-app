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

// The board's two click actions (the operator's moderation: onModerate, a Like / Unlike:
// onToggleLike) say why a refused click was refused, the way the reply paths do (app#432,
// the two #425 left out): onModerate showed 'connection error' for ANY HTTP failure, and
// onToggleLike dropped a non-ok response without a word. Now a failed response shows the
// server's own sentence as TEXT in #pane-board-action-msg (serverErrorText -> textContent),
// the generic HTTP sentence only when the response has none, and a later success leaves no
// refusal on screen. Same limits as above: the document and fetch are fakes.

// boardActionResult is what the driver reports after one run of a click handler.
type boardActionResult struct {
	URL      string `json:"url"`
	Msg      string `json:"msg"`
	Cls      string `json:"cls"`
	Hidden   bool   `json:"hidden"`
	Updated  string `json:"updated"`
	Rendered int    `json:"rendered"`
	Reloads  int    `json:"reloads"`
	SigReset bool   `json:"sigReset"`
}

// runBoardAction runs the two handlers' source (moderateJS, likeJS: the real text, or a
// mutation of it) through the scenarios and returns "<moderate|like>.<scenario>" -> result.
func runBoardAction(t *testing.T, moderateJS, likeJS string) map[string]boardActionResult {
	t.Helper()
	parts := portalPartials(t)
	util, pane := partialBody(parts, "core-util.tmpl"), partialBody(parts, "pane-board.tmpl")
	var rules strings.Builder
	rules.WriteString(extractJSConst(t, util, "serverErrorText") + "\n")
	rules.WriteString(extractJSFunc(t, pane, "showActionMsg") + "\n")
	rules.WriteString(moderateJS + "\n" + likeJS + "\n")
	driver := `
var selectedTid = 't1', builtView = 'thread:t1', currentTh = { id: 't1' }, lastListSig = 'x', lastPublicSig = 'x';
var rendered = 0, reloads = 0, urls = [], mode = 'ok';
var updatedEl = { textContent: '' };
// The message element is the open shell's: one per view, found by id on each call.
var actionMsgEl = { textContent: '', className: 'submit-msg', hidden: true };
var document = { getElementById: function (id) { return id === 'pane-board-action-msg' ? actionMsgEl : null; } };
function renderThread() { rendered++; }
function loadThread() { reloads++; return Promise.resolve(); }
function loadList() { reloads++; return Promise.resolve(); }
// A Response body is ONE-SHOT, as in Fetch (see runBoardSend).
function resp(status, ok, parse) {
  var bodyUsed = false;
  return { status: status, ok: ok, get bodyUsed() { return bodyUsed; }, json: function () {
    if (bodyUsed) return Promise.reject(new TypeError('Body has already been consumed.'));
    bodyUsed = true; return parse();
  } };
}
var fetch = function (url) {
  urls.push(url);
  // The operator opens another thread while the request is in flight.
  if (mode === 'switched') { selectedTid = 't2'; builtView = 'thread:t2'; return Promise.resolve(resp(403, false, function () { return Promise.resolve({ error: 'admin only' }); })); }
  if (mode === 'forbidden') return Promise.resolve(resp(403, false, function () { return Promise.resolve({ error: '<img src=x onerror=alert(1)>' }); }));
  if (mode === 'server') return Promise.resolve(resp(500, false, function () { return Promise.resolve({ error: 'internal error' }); }));
  if (mode === 'nobody') return Promise.resolve(resp(403, false, function () { return Promise.reject(new Error('not json')); }));
  if (mode === 'rate') return Promise.resolve(resp(429, false, function () { return Promise.resolve({ error: 'slow down' }); }));
  if (mode === 'down') return Promise.reject(new TypeError('Failed to fetch'));
  return Promise.resolve(resp(200, true, function () { return Promise.resolve({ id: 't1' }); }));
};
var paths = {
  moderate: function () { return onModerate({ pinned: true }); },
  like:     function () { return onToggleLike('t1', false); },
  unlike:   function () { return onToggleLike('t1', true); },
  // The Public Timeline's inline button: the list view is open, no thread is selected.
  likeList: function () { selectedTid = null; builtView = 'list'; lastPublicSig = 'x'; return onToggleLike('t1', false); },
};
// keep: the earlier attempt's message stays on screen (the element is never rebuilt).
function run(which, m, keep) {
  mode = m; rendered = 0; reloads = 0; urls.length = 0; updatedEl.textContent = '';
  selectedTid = 't1'; builtView = 'thread:t1';
  if (!keep) { actionMsgEl.textContent = ''; actionMsgEl.className = 'submit-msg'; actionMsgEl.hidden = true; }
  return paths[which]().then(function () {
    return { url: urls[0], msg: actionMsgEl.textContent, cls: actionMsgEl.className, hidden: actionMsgEl.hidden, updated: updatedEl.textContent, rendered: rendered, reloads: reloads, sigReset: lastPublicSig === null };
  });
}
var out = {};
var chain = Promise.resolve();
['moderate', 'like'].forEach(function (w) {
  chain = chain
    .then(function () { return run(w, 'forbidden'); }).then(function (r) { out[w + '.forbidden'] = r; })
    .then(function () { return run(w, 'server'); }).then(function (r) { out[w + '.server'] = r; })
    .then(function () { return run(w, 'nobody'); }).then(function (r) { out[w + '.nobody'] = r; })
    .then(function () { return run(w, 'rate'); }).then(function (r) { out[w + '.rate'] = r; })
    .then(function () { return run(w, 'down'); }).then(function (r) { out[w + '.down'] = r; })
    .then(function () { return run(w, 'switched'); }).then(function (r) { out[w + '.switched'] = r; })
    // Each click starts by clearing the earlier refusal, whatever it ends with.
    .then(function () { return run(w, 'forbidden'); })
    .then(function () { return run(w, 'rate', true); }).then(function (r) { out[w + '.rateAfterRefusal'] = r; })
    .then(function () { return run(w, 'forbidden'); })
    .then(function () { return run(w, 'down', true); }).then(function (r) { out[w + '.downAfterRefusal'] = r; })
    .then(function () { return run(w, 'forbidden'); })
    .then(function () { return run(w, 'ok', true); }).then(function (r) { out[w + '.recovered'] = r; });
});
['unlike', 'likeList'].forEach(function (w) {
  chain = chain
    .then(function () { return run(w, 'forbidden'); }).then(function (r) { out[w + '.forbidden'] = r; })
    .then(function () { return run(w, 'ok', true); }).then(function (r) { out[w + '.recovered'] = r; });
});
`
	var got map[string]boardActionResult
	runJS(t, rules.String(), driver, nil, &got)
	return got
}

func TestBoardActions_ShowTheServerSentenceAndClearItOnSuccess(t *testing.T) {
	got := runBoardAction(t, boardHandlerJS(t, "onModerate"), boardHandlerJS(t, "onToggleLike"))
	for _, w := range []struct{ name, url, generic string }{
		{"moderate", "/api/admin/board/threads/t1/state", "Could not update the thread (HTTP 403)."},
		{"like", "/api/board/threads/t1/like", "Could not update the like (HTTP 403)."},
	} {
		t.Run(w.name, func(t *testing.T) {
			for _, k := range []string{"forbidden", "server", "nobody", "rate", "down", "switched", "rateAfterRefusal", "downAfterRefusal", "recovered"} {
				if _, ok := got[w.name+"."+k]; !ok {
					t.Fatalf("%s: the scenario did not finish", k)
				}
			}
			if f := got[w.name+".forbidden"]; f.URL != w.url || f.Msg != "<img src=x onerror=alert(1)>" || !strings.Contains(f.Cls, "err") || f.Hidden || f.Rendered != 0 || f.Reloads != 0 || f.Updated != "" {
				t.Errorf("a 403 must show the server's sentence as text (no markup is made of it), repaint nothing, and not claim a connection error: %+v", f)
			}
			if s := got[w.name+".server"]; s.Msg != "internal error" || !strings.Contains(s.Cls, "err") || s.Hidden || s.Updated != "" {
				t.Errorf("a 500 with a body shows that body, not 'connection error': %+v", s)
			}
			if n := got[w.name+".nobody"]; n.Msg != w.generic || !strings.Contains(n.Cls, "err") || n.Hidden || n.Updated != "" {
				t.Errorf("a failure without a JSON body falls back to the HTTP status sentence %q: %+v", w.generic, n)
			}
			if d := got[w.name+".down"]; d.Updated != "connection error" || d.Msg != "" {
				t.Errorf("a transport failure keeps the connection-error status line and puts nothing in the action message: %+v", d)
			}
			if sw := got[w.name+".switched"]; sw.Msg != "" || !sw.Hidden {
				t.Errorf("a refusal that arrives after the operator moved to another view is dropped (the element now belongs to that view): %+v", sw)
			}
			ks := []string{"downAfterRefusal"}
			if w.name == "like" { // an operator's 429 is a refusal with the server's sentence, shown here
				ks = append(ks, "rateAfterRefusal")
			}
			for _, k := range ks {
				if r := got[w.name+"."+k]; r.Msg != "" || r.Cls != "submit-msg" || !r.Hidden {
					t.Errorf("%s: a click starts by clearing the earlier refusal, so a 429 / transport failure leaves none behind: %+v", k, r)
				}
			}
			if r := got[w.name+".recovered"]; r.Msg != "" || r.Cls != "submit-msg" || !r.Hidden || r.Rendered+r.Reloads != 1 {
				t.Errorf("a click that works after a refusal must clear the refusal (text, err class, shown) and repaint once: %+v", r)
			}
		})
	}
	// The Unlike button and the list view's inline Like use the same handler: the other
	// URL, and the list is what is repainted.
	if u := got["unlike.forbidden"]; u.URL != "/api/board/threads/t1/unlike" || u.Msg != "<img src=x onerror=alert(1)>" || !strings.Contains(u.Cls, "err") {
		t.Errorf("an Unlike refused with a 403 shows the server's sentence: %+v", u)
	}
	if r := got["unlike.recovered"]; r.Msg != "" || !r.Hidden || r.Reloads != 1 || r.SigReset {
		t.Errorf("an Unlike that works clears the refusal and reloads the open thread, not the list: %+v", r)
	}
	if l := got["likeList.forbidden"]; l.URL != "/api/board/threads/t1/like" || l.Msg != "<img src=x onerror=alert(1)>" || !strings.Contains(l.Cls, "err") || l.Hidden {
		t.Errorf("a Like refused on the list view shows the server's sentence: %+v", l)
	}
	if r := got["likeList.recovered"]; r.Msg != "" || !r.Hidden || r.Reloads != 1 || !r.SigReset {
		t.Errorf("a Like that works on the list view clears the refusal and repaints the list (signature reset): %+v", r)
	}
	// A like that hits the rate limit keeps its own status-line sentence; the action
	// message is for the refusals that had none.
	if r := got["like.rate"]; r.Updated != "rate limited — try again in a moment" || r.Msg != "" {
		t.Errorf("a 429 on a like says so on the status line and leaves the action message alone: %+v", r)
	}
}

// TestBoardActions_MockCatchesTheBodyReadBeforeTheStatusCheck: as for the reply paths, a
// handler that reads r.json() BEFORE `if (!r.ok)` leaves serverErrorText nothing to read,
// and the mock's one-shot Response turns that into a lost sentence.
func TestBoardActions_MockCatchesTheBodyReadBeforeTheStatusCheck(t *testing.T) {
	mutate := func(js string) string {
		const gate = "if (!r.ok) {"
		if strings.Count(js, gate) != 1 {
			t.Fatalf("want exactly one %q in the handler to mutate", gate)
		}
		return strings.Replace(js, gate, "await r.json().catch(() => ({}));\n        "+gate, 1)
	}
	got := runBoardAction(t, mutate(boardHandlerJS(t, "onModerate")), mutate(boardHandlerJS(t, "onToggleLike")))
	for _, w := range []string{"moderate", "like"} {
		if f := got[w+".forbidden"]; f.Msg == "<img src=x onerror=alert(1)>" {
			t.Errorf("%s: the mutated handler (body read before the status check) still shows the server's sentence: the mock does not enforce one read", w)
		}
	}
}
