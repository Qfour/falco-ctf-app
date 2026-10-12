//go:build e2e

package e2e

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

// selfTestSite serves internal/e2e/testdata/selftest: small pages, each with one
// planted defect, behind the same Proxy and browser the scenarios use. /api/*
// answers 200 to any method so a page's POST has somewhere to go; a page that
// needs a response header (a CSP) gets it from headers.
func selfTestSite(t *testing.T, headers map[string]string) *harness.Site {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", "selftest"))
	if err != nil {
		t.Fatal(err)
	}
	files := http.FileServer(http.Dir(dir))
	site, err := harness.NewSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if h, ok := headers[r.URL.Path]; ok {
			w.Header().Set("Content-Security-Policy", h)
		}
		files.ServeHTTP(w, r)
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(site.Close)
	return site
}

func selfTestBrowser(t *testing.T, headers map[string]string) *Browser {
	t.Helper()
	site := selfTestSite(t, headers)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := harness.NewProxy(ln, site, "user1@"+harness.IdentityDomain)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)
	return NewBrowser(t, BrowserConfig{
		Proxy:     proxy,
		HostRules: harness.HostResolverRules(nil),
	})
}

// TestSelfTest_SharedAssertionsTurnRedOnPlantedDefects is ADR-0031 V2: a check
// that has never been seen to fail proves nothing, so each planted defect below
// must be reported by the shared assertion meant to catch it — and the clean
// pages must report nothing, so the assertions are not red for everything.
func TestSelfTest_SharedAssertionsTurnRedOnPlantedDefects(t *testing.T) {
	const strict = "default-src 'self'"
	cases := []struct {
		name string
		page string
		// headers: response headers by path (a CSP).
		headers map[string]string
		// click: a selector the "person" clicks once before the page is judged.
		click string
		// writes: what the person did (the proxy must have seen exactly this).
		writes []string
		// want: checks that must fire. wantNot: checks that must stay quiet.
		want    []string
		wantNot []string
	}{
		{name: "a clean page reports nothing", page: "/clean.html"},
		{name: "(a) a POST at load time", page: "/post-on-load.html",
			want: []string{CheckWrites}, wantNot: []string{CheckConsole, CheckException, CheckCSP, CheckExternal}},
		{name: "(b) a CSP violation in head", page: "/csp-head.html",
			headers: map[string]string{"/csp-head.html": strict},
			want:    []string{CheckCSP}, wantNot: []string{CheckWrites, CheckExternal, CheckException}},
		{name: "(c) an uncaught error", page: "/uncaught.html",
			want: []string{CheckException}, wantNot: []string{CheckWrites, CheckCSP, CheckExternal, CheckConnection}},
		{name: "(d) a request to an external origin", page: "/external.html",
			want: []string{CheckExternal}, wantNot: []string{CheckWrites, CheckCSP, CheckException}},
		{name: "(e) a caught render exception shown as connection error", page: "/connection-error.html",
			want: []string{CheckConnection}, wantNot: []string{CheckException, CheckConsole, CheckWrites, CheckCSP}},
		{name: "(f) a POST by itself two seconds after load", page: "/auto-post-after-2s.html",
			want: []string{CheckWrites}, wantNot: []string{CheckException, CheckCSP}},
		{name: "(g) one click that POSTs twice", page: "/double-post-on-click.html", click: "#go",
			writes: []string{"POST /api/click"},
			want:   []string{CheckWrites}, wantNot: []string{CheckException, CheckCSP}},
		{name: "one click that POSTs once is what the person did", page: "/single-post-on-click.html", click: "#go",
			writes: []string{"POST /api/click"}},
		{name: "a console.error", page: "/console-error.html",
			want: []string{CheckConsole}, wantNot: []string{CheckException, CheckWrites, CheckCSP}},
		{name: "a dialog nobody expected", page: "/dialog.html",
			want: []string{CheckDialog}, wantNot: []string{CheckException, CheckWrites, CheckCSP}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := selfTestBrowser(t, c.headers)
			b.Open(c.page)
			if c.click != "" {
				b.Click(c.click)
			}
			b.Wait("the page to finish", `document.documentElement.dataset.done === '1'`)
			vs := b.Report(0, c.writes)
			if len(c.want) == 0 && len(vs) != 0 {
				t.Errorf("a page with nothing wrong was reported: %v", vs)
			}
			for _, want := range c.want {
				if !Has(vs, want) {
					t.Errorf("planted defect not caught: no %q violation. Reported: %v", want, vs)
				}
			}
			for _, not := range c.wantNot {
				if Has(vs, not) {
					t.Errorf("check %q fired on a page that has no such defect. Reported: %v", not, vs)
				}
			}
		})
	}
}

// A page that is fine but a person who did something else: the writes check is
// about the proxy's record, not about the page, so a missing write is a
// difference as well.
func TestSelfTest_AMissingWriteIsADifference(t *testing.T) {
	b := selfTestBrowser(t, nil)
	b.Open("/clean.html")
	b.Wait("the page to finish", `document.documentElement.dataset.done === '1'`)
	if vs := b.Report(0, []string{"POST /api/click"}); !Has(vs, CheckWrites) {
		t.Errorf("the person's POST never reached the proxy but no writes violation was reported: %v", vs)
	}
}

// The browser is launched only from the harness's allowlist and only from the
// real binary; a missing binary is an error, never a skip (V6).
func TestSelfTest_BrowserIsMissingIsAnError(t *testing.T) {
	t.Setenv("E2E_CHROMIUM", filepath.Join(t.TempDir(), "no-such-browser"))
	if _, err := harness.ChromiumPath(os.Getenv, os.Stat); err == nil {
		t.Fatal("ChromiumPath accepted a browser that is not there")
	}
}

// V3, the live half: the command line Chromium really runs with is read back
// from /proc and holds only allowlisted switches, chromedp's own, and
// about:blank. NewBrowser already refuses a browser that fails this; the test
// states it independently, and checks the pieces the isolation depends on are
// really there (a check that reads an empty line would pass for anything).
func TestSelfTest_ChromiumRunsWithOnlyAllowlistedArgv(t *testing.T) {
	b := selfTestBrowser(t, nil)
	argv, err := b.Argv()
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.CheckArgv(b.bin, argv); err != nil {
		t.Fatalf("%v\nargv: %q", err, argv)
	}
	joined := "\x00" + strings.Join(argv, "\x00") + "\x00"
	for _, want := range []string{"--headless", "--host-resolver-rules=", "--disable-extensions", "--user-data-dir="} {
		if !strings.Contains(joined, "\x00"+want) {
			t.Errorf("the live command line has no %s: %q", want, argv)
		}
	}
	if len(argv) < 10 {
		t.Errorf("the live command line is suspiciously short: %q", argv)
	}
}
