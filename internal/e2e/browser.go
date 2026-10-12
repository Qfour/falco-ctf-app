//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// The checks every scenario shares (ADR-0031 D2). A Violation carries the name
// of the check that fired, so the self-test can say which assertion caught a
// planted defect.
const (
	CheckException   = "uncaught-exception"
	CheckConsole     = "console-error"
	CheckConnection  = "connection-error"
	CheckCSP         = "csp-violation"
	CheckExternal    = "external-origin"
	CheckDialog      = "unexpected-dialog"
	CheckWrites      = "writes"
	bindingCSP       = "__e2eCSP"
	bindingConn      = "__e2eConn"
	bindingFlush     = "__e2eFlush"
	flushConsoleTag  = "__e2e_flush:"
	defaultWaitLimit = 45 * time.Second
)

// Violation is one failed shared check.
type Violation struct {
	Check  string
	Detail string
}

func (v Violation) String() string { return v.Check + ": " + v.Detail }

// Dialog is a native dialog the page opened.
type Dialog struct {
	Type    string
	Message string
}

type dialogPolicy struct {
	accept bool
	reply  chan Dialog
}

// BrowserConfig is what one browser needs to know about the run.
type BrowserConfig struct {
	// Proxy is what the page talks to; its origin is the only origin (besides
	// ExtraOrigins) the page may request.
	Proxy *harness.Proxy
	// ExtraOrigins are further origins that are allowed (the ttyd stub).
	ExtraOrigins []string
	// HostRules and SPKIHash configure the ttyd stub mapping (see harness).
	HostRules string
	SPKIHash  string
	// ReducedMotion is the prefers-reduced-motion value ("reduce" or
	// "no-preference"); empty means "reduce" (ADR-0031 D3).
	ReducedMotion string
}

// Browser is one headless Chromium tab with the shared collectors attached
// before its first navigation.
type Browser struct {
	t       *testing.T
	proxy   *harness.Proxy
	allowed map[string]bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu          sync.Mutex
	cond        *sync.Cond
	violations  []Violation
	consoleLog  []string
	dialogs     []Dialog
	dialogQueue []dialogPolicy
	flushSeen   map[string]int // "console:N" / "binding:N" / "network:N" -> seen
	flushSeq    int
}

// initScript runs in every document before any of its scripts (the page cannot
// order itself ahead of it, and CDP-injected scripts are exempt from the page's
// CSP, so the observer works under the portal's strict policy without
// Page.setBypassCSP). It reports
//   - securitypolicyviolation events, and
//   - any text node (outside script/style) that reads "connection error", the
//     portal's only visible trace of a render exception (they are caught by the
//     refresh() try and never reach window.onerror: ADR-0031 C4). A MutationObserver
//     sees the flash even when the next poll replaces it.
const initScript = `(function () {
  var send = function (name, payload) {
    try { if (typeof window[name] === 'function') window[name](JSON.stringify(payload)); } catch (e) {}
  };
  document.addEventListener('securitypolicyviolation', function (e) {
    send('` + bindingCSP + `', { directive: e.violatedDirective, blocked: e.blockedURI, source: e.sourceFile || '', line: e.lineNumber || 0 });
  }, true);
  var re = /connection error/i;
  var skip = function (n) { var p = n.parentElement; return p && (p.tagName === 'SCRIPT' || p.tagName === 'STYLE'); };
  var scan = function (n) {
    if (n.nodeType === 3) {
      if (re.test(n.data) && !skip(n)) send('` + bindingConn + `', { in: (n.parentElement && (n.parentElement.id || n.parentElement.tagName)) || '?', text: n.data.slice(0, 80) });
    } else if (n.nodeType === 1 && n.tagName !== 'SCRIPT' && n.tagName !== 'STYLE') {
      for (var c = n.firstChild; c; c = c.nextSibling) scan(c);
    }
  };
  new MutationObserver(function (muts) {
    for (var i = 0; i < muts.length; i++) {
      var m = muts[i];
      if (m.type === 'characterData') scan(m.target);
      else for (var j = 0; j < m.addedNodes.length; j++) scan(m.addedNodes[j]);
    }
  }).observe(document, { subtree: true, childList: true, characterData: true });
})();`

// NewBrowser starts Chromium with the harness's flag allowlist, attaches every
// collector, applies the fixed emulation (1280x800, ja-JP, Asia/Tokyo) and
// returns a tab that has not navigated yet.
func NewBrowser(t *testing.T, cfg BrowserConfig) *Browser {
	t.Helper()
	path, err := harness.ChromiumPath(os.Getenv, os.Stat)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := harness.ChromiumFlags(harness.LaunchConfig{HostRules: cfg.HostRules, SPKIHash: cfg.SPKIHash})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(path),
		chromedp.UserDataDir(filepath.Join(home, "profile")),
		// Nothing of the parent's environment reaches the browser.
		chromedp.NoInheritEnv,
		chromedp.Env("HOME="+home, "PATH=/usr/bin:/bin", "LANG=ja_JP.UTF-8", "TZ=Asia/Tokyo"),
	}
	for _, f := range flags {
		opts = append(opts, chromedp.Flag(f.Name, f.Value))
	}

	b := &Browser{t: t, proxy: cfg.Proxy, allowed: map[string]bool{cfg.Proxy.Origin(): true}, flushSeen: map[string]int{}}
	b.cond = sync.NewCond(&b.mu)
	for _, o := range cfg.ExtraOrigins {
		b.allowed[o] = true
	}
	actx, acancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(actx)
	b.ctx = ctx
	b.cancel = func() { cancel(); acancel() }

	// Subscribe before anything runs: Events/Console start the browser and
	// open the tab, and nothing the page does is lost afterwards.
	b.collect(chromedp.Console(ctx), b.onConsole)
	b.collectEvents(ctx)

	motion := cfg.ReducedMotion
	if motion == "" {
		motion = "reduce"
	}
	setup := func() error {
		if _, err := chromedp.Call(ctx, network.Enable, network.EnableParams{}); err != nil {
			return fmt.Errorf("Network.enable: %w", err)
		}
		if _, err := chromedp.Call(ctx, page.Enable, page.EnableParams{}); err != nil {
			return fmt.Errorf("Page.enable: %w", err)
		}
		for _, name := range []string{bindingCSP, bindingConn, bindingFlush} {
			if _, err := chromedp.Call(ctx, runtime.AddBinding, runtime.AddBindingParams{Name: name}); err != nil {
				return fmt.Errorf("Runtime.addBinding %s: %w", name, err)
			}
		}
		if _, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: initScript}); err != nil {
			return fmt.Errorf("Page.addScriptToEvaluateOnNewDocument: %w", err)
		}
		if _, err := chromedp.Call(ctx, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{Width: 1280, Height: 800, DeviceScaleFactor: 1}); err != nil {
			return fmt.Errorf("Emulation.setDeviceMetricsOverride: %w", err)
		}
		if _, err := chromedp.Call(ctx, emulation.SetLocaleOverride, emulation.SetLocaleOverrideParams{Locale: "ja-JP"}); err != nil {
			return fmt.Errorf("Emulation.setLocaleOverride: %w", err)
		}
		if _, err := chromedp.Call(ctx, emulation.SetTimezoneOverride, emulation.SetTimezoneOverrideParams{TimezoneID: "Asia/Tokyo"}); err != nil {
			return fmt.Errorf("Emulation.setTimezoneOverride: %w", err)
		}
		if _, err := chromedp.Call(ctx, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
			Features: []*emulation.MediaFeature{{Name: "prefers-reduced-motion", Value: motion}},
		}); err != nil {
			return fmt.Errorf("Emulation.setEmulatedMedia: %w", err)
		}
		return nil
	}
	if err := setup(); err != nil {
		b.Close()
		t.Fatalf("browser setup: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			b.dumpDiagnostics()
		}
		b.Close()
	})
	return b
}

// Close stops the browser and the collector goroutines.
func (b *Browser) Close() {
	b.cancel()
	b.wg.Wait()
}

func (b *Browser) add(v Violation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.violations = append(b.violations, v)
}

// collect runs fn for every console message until the context ends.
func (b *Browser) collect(msgs func(yield func(chromedp.ConsoleMessage, error) bool), fn func(chromedp.ConsoleMessage)) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		msgs(func(m chromedp.ConsoleMessage, err error) bool {
			if err != nil {
				return false
			}
			fn(m)
			return true
		})
	}()
}

func (b *Browser) onConsole(m chromedp.ConsoleMessage) {
	line := fmt.Sprintf("[%s] %s", m.Type, m.Text)
	if m.URL != "" {
		line += fmt.Sprintf(" (%s:%d)", m.URL, m.Line)
	}
	b.mu.Lock()
	b.consoleLog = append(b.consoleLog, line)
	b.mu.Unlock()

	if strings.HasPrefix(m.Text, flushConsoleTag) {
		b.flushed("console:" + strings.TrimPrefix(m.Text, flushConsoleTag))
		return
	}
	switch {
	case m.IsException():
		b.add(Violation{CheckException, line})
	case m.Type == chromedp.ConsoleError:
		b.add(Violation{CheckConsole, line})
		// The browser reports a blocked resource or script as a "security"
		// log entry: that arrives synchronously with the violation, unlike
		// the DOM event.
		if m.Source == "security" || strings.Contains(m.Text, "Content Security Policy") {
			b.add(Violation{CheckCSP, line})
		}
	}
}

func (b *Browser) flushed(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushSeen[key]++
	b.cond.Broadcast()
}

func (b *Browser) collectEvents(ctx context.Context) {
	reqs := chromedp.Events(ctx, network.RequestWillBeSent)
	binds := chromedp.Events(ctx, runtime.BindingCalled)
	dialogs := chromedp.Events(ctx, page.JavascriptDialogOpening)

	b.wg.Add(3)
	go func() {
		defer b.wg.Done()
		for ev, err := range reqs {
			if err != nil {
				return
			}
			b.onRequest(ev)
		}
	}()
	go func() {
		defer b.wg.Done()
		for ev, err := range binds {
			if err != nil {
				return
			}
			b.onBinding(ev)
		}
	}()
	go func() {
		defer b.wg.Done()
		for ev, err := range dialogs {
			if err != nil {
				return
			}
			b.onDialog(ctx, ev)
		}
	}()
}

func (b *Browser) onRequest(ev network.EventRequestWillBeSent) {
	raw := ev.Request.URL
	u, err := url.Parse(raw)
	if err != nil {
		b.add(Violation{CheckExternal, "unparsable request URL " + strconv.Quote(raw)})
		return
	}
	if u.Path == harness.FlushPath && u.Scheme+"://"+u.Host == b.proxy.Origin() {
		b.flushed("network:" + u.Query().Get("n"))
		return
	}
	switch u.Scheme {
	case "data", "blob", "about", "chrome-error":
		return // same-document or browser-internal: no network
	}
	origin := u.Scheme + "://" + u.Host
	if !b.allowed[origin] {
		b.add(Violation{CheckExternal, ev.Request.Method + " " + raw})
	}
}

func (b *Browser) onBinding(ev runtime.EventBindingCalled) {
	switch ev.Name {
	case bindingCSP:
		b.add(Violation{CheckCSP, "securitypolicyviolation " + ev.Payload})
	case bindingConn:
		b.add(Violation{CheckConnection, "the page showed \"connection error\" " + ev.Payload})
	case bindingFlush:
		b.flushed("binding:" + strings.Trim(ev.Payload, `"`))
	}
}

func (b *Browser) onDialog(ctx context.Context, ev page.EventJavascriptDialogOpening) {
	b.mu.Lock()
	var pol *dialogPolicy
	if len(b.dialogQueue) > 0 {
		p := b.dialogQueue[0]
		b.dialogQueue = b.dialogQueue[1:]
		pol = &p
	}
	d := Dialog{Type: string(ev.Type), Message: ev.Message}
	b.dialogs = append(b.dialogs, d)
	b.mu.Unlock()

	accept := false // an unexpected dialog is dismissed
	if pol != nil {
		accept = pol.accept
	} else {
		b.add(Violation{CheckDialog, fmt.Sprintf("%s %q opened with no ExpectDialog", d.Type, d.Message)})
	}
	if _, err := chromedp.Call(ctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: accept}); err != nil && ctx.Err() == nil {
		b.add(Violation{CheckDialog, "could not answer the dialog: " + err.Error()})
	}
	if pol != nil {
		pol.reply <- d
	}
}

// ExpectDialog registers the answer to the next native dialog (true = OK). The
// returned channel receives the dialog once it has been answered. A dialog that
// nobody expected is dismissed and fails the run (CheckDialog).
func (b *Browser) ExpectDialog(accept bool) <-chan Dialog {
	ch := make(chan Dialog, 1)
	b.mu.Lock()
	b.dialogQueue = append(b.dialogQueue, dialogPolicy{accept: accept, reply: ch})
	b.mu.Unlock()
	return ch
}

// AwaitDialog waits for a dialog registered with ExpectDialog.
func (b *Browser) AwaitDialog(ch <-chan Dialog, what string) Dialog {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(b.ctx, defaultWaitLimit)
	defer cancel()
	select {
	case d := <-ch:
		return d
	case <-ctx.Done():
		b.t.Fatalf("waiting for the %s dialog: %v\n%s", what, ctx.Err(), b.diagnostics())
		return Dialog{}
	}
}

// Dialogs returns every dialog the page has opened so far.
func (b *Browser) Dialogs() []Dialog {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Dialog(nil), b.dialogs...)
}

// --- driving the page ---

// URL joins path to the proxy's origin.
func (b *Browser) URL(path string) string { return b.proxy.Origin() + path }

func (b *Browser) limited() (context.Context, context.CancelFunc) {
	return context.WithTimeout(b.ctx, defaultWaitLimit)
}

// Open navigates to path on the proxy and waits for the load event.
func (b *Browser) Open(path string) {
	b.t.Helper()
	ctx, cancel := b.limited()
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Navigate(b.URL(path))); err != nil {
		b.t.Fatalf("open %s: %v\n%s", path, err, b.diagnostics())
	}
}

// Reload reloads the page and waits for the load event.
func (b *Browser) Reload() {
	b.t.Helper()
	ctx, cancel := b.limited()
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Reload()); err != nil {
		b.t.Fatalf("reload: %v\n%s", err, b.diagnostics())
	}
}

// Click clicks the first element matching the CSS selector.
func (b *Browser) Click(selector string) {
	b.t.Helper()
	ctx, cancel := b.limited()
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Click(chromedp.CSS(selector))); err != nil {
		b.t.Fatalf("click %s: %v\n%s", selector, err, b.diagnostics())
	}
}

// Wait blocks until the JavaScript predicate is truthy. The page re-evaluates it
// on every DOM mutation (no timer of ours), and the deadline only bounds how long
// a failure takes to appear.
func (b *Browser) Wait(what, predicate string) {
	b.t.Helper()
	ctx, cancel := b.limited()
	defer cancel()
	_, err := chromedp.Run(ctx, chromedp.Poll[bool](predicate, chromedp.WithPollingMutation(), chromedp.WithPollingTimeout(defaultWaitLimit)))
	if err != nil {
		b.t.Fatalf("waiting for %s: %v\n  predicate: %s\n%s", what, err, predicate, b.diagnostics())
	}
}

// Eval evaluates a JavaScript expression and decodes its value.
func Eval[T any](b *Browser, expr string) T {
	b.t.Helper()
	ctx, cancel := b.limited()
	defer cancel()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[T](expr))
	if err != nil {
		b.t.Fatalf("evaluate %q: %v\n%s", expr, err, b.diagnostics())
	}
	return v
}

// WaitProxy waits on the proxy's log (see harness.Proxy.Wait).
func (b *Browser) WaitProxy(what string, pred func(log []harness.Entry) bool) {
	b.t.Helper()
	ctx, cancel := b.limited()
	defer cancel()
	if err := b.proxy.Wait(ctx, what, pred); err != nil {
		b.t.Fatalf("%v\n%s", err, b.diagnostics())
	}
}

// Flush returns once every event the page produced before the call has been
// handled by the collectors. The collectors run on their own goroutines, so a
// check made right after the page's last visible effect could otherwise run
// before the corresponding event is looked at. It sends one marker through each
// pipeline (console, binding, network) and waits for all three to come back.
func (b *Browser) Flush() {
	b.t.Helper()
	b.mu.Lock()
	b.flushSeq++
	n := strconv.Itoa(b.flushSeq)
	b.mu.Unlock()
	expr := fmt.Sprintf(`(function(){ console.log(%q); window.%s(%q); fetch(%q).catch(function(){}); return true; })()`,
		flushConsoleTag+n, bindingFlush, n, harness.FlushPath+"?n="+n)
	ctx, cancel := b.limited()
	defer cancel()
	if _, err := chromedp.Run(ctx, chromedp.Evaluate[bool](expr)); err != nil {
		b.t.Fatalf("flush: %v\n%s", err, b.diagnostics())
	}
	if missing := b.awaitFlush(ctx, n); missing != "" {
		b.t.Fatalf("flush: the %s marker never came back: %v\n%s", missing, ctx.Err(), b.diagnostics())
	}
}

// awaitFlush waits for the three markers of round n; it returns the name of the
// first one still missing when ctx ends, or "".
func (b *Browser) awaitFlush(ctx context.Context, n string) string {
	stop := context.AfterFunc(ctx, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.cond.Broadcast()
	})
	defer stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range []string{"console:" + n, "binding:" + n, "network:" + n} {
		for b.flushSeen[k] == 0 {
			if ctx.Err() != nil {
				return k
			}
			b.cond.Wait()
		}
	}
	return ""
}

var connectionErrorRE = regexp.MustCompile(`(?i)connection error`)

// Report runs the shared checks (ADR-0031 D2) and returns what they found:
//   - uncaught errors, console errors, CSP violations, "connection error"
//     shown anywhere, requests to an origin other than the proxy's and the ttyd
//     stub's, and unexpected native dialogs (collected since the browser started);
//   - the write requests (everything but GET) the proxy saw after mark must be
//     exactly wantWrites, in order: an unexpected POST, a missing one or a
//     doubled one are all a difference. "Exactly" is the point — the sequence
//     of writes is the sequence of things the person did.
func (b *Browser) Report(mark int, wantWrites []string) []Violation {
	b.t.Helper()
	b.Flush()
	b.mu.Lock()
	out := append([]Violation(nil), b.violations...)
	b.mu.Unlock()

	// What is on screen right now, in addition to what the observer saw.
	for _, hit := range Eval[[]string](b, visibleConnectionErrors) {
		out = append(out, Violation{CheckConnection, "the page shows \"connection error\" in " + hit})
	}
	got := b.proxy.Writes(mark)
	if strings.Join(got, "\n") != strings.Join(wantWrites, "\n") {
		out = append(out, Violation{CheckWrites, fmt.Sprintf("write requests after the mark = %q, the person's actions = %q", got, wantWrites)})
	}
	return out
}

// visibleConnectionErrors lists the elements whose own text (not script/style)
// reads "connection error" right now.
const visibleConnectionErrors = `(function () {
  var out = [];
  if (!document.body) return out;
  var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (w.nextNode()) {
    var n = w.currentNode, p = n.parentElement;
    if (p && p.tagName !== 'SCRIPT' && p.tagName !== 'STYLE' && /connection error/i.test(n.data)) out.push(p.id || p.tagName);
  }
  return out;
})()`

// AssertClean fails t for every violation Report finds.
func (b *Browser) AssertClean(mark int, wantWrites []string) {
	b.t.Helper()
	for _, v := range b.Report(mark, wantWrites) {
		b.t.Errorf("shared check failed: %s", v)
	}
}

// Has reports whether the violations include one of the named check.
func Has(vs []Violation, check string) bool {
	for _, v := range vs {
		if v.Check == check {
			return true
		}
	}
	return false
}

// --- diagnostics ---

func (b *Browser) diagnostics() string {
	var sb strings.Builder
	sb.WriteString("--- proxy log ---\n")
	sb.WriteString(harness.FormatLog(b.proxy.Entries()))
	b.mu.Lock()
	sb.WriteString("--- console ---\n")
	for _, l := range b.consoleLog {
		sb.WriteString("  " + l + "\n")
	}
	sb.WriteString("--- violations so far ---\n")
	for _, v := range b.violations {
		sb.WriteString("  " + v.String() + "\n")
	}
	b.mu.Unlock()
	return sb.String()
}

// dumpDiagnostics writes a screenshot, the DOM text and the logs under
// E2E_DIAG_DIR/<test name> (the run script exports that directory).
func (b *Browser) dumpDiagnostics() {
	dir := os.Getenv("E2E_DIAG_DIR")
	if dir == "" {
		return
	}
	dir = filepath.Join(dir, strings.ReplaceAll(b.t.Name(), "/", "_"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "diagnostics.txt"), []byte(b.diagnostics()), 0o644)
	if b.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	if png, err := chromedp.Run(ctx, chromedp.CaptureScreenshot()); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "screen.png"), png, 0o644)
	}
	if txt, err := chromedp.Run(ctx, chromedp.Evaluate[string](`document.body ? document.body.innerText : ''`)); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "body.txt"), []byte(txt), 0o644)
	}
}

var errNoBinary = errors.New("E2E_SCOREBOARD_BIN is not set: Dockerfile.e2e builds the binary and run.sh passes its path")
