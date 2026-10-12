package apispec

// ADR-0031 V3 / V4 / V8: the machine-checked boundaries around the browser E2E
// harness (internal/e2e). Everything here runs in `make test` (a required
// check), without Chromium: the harness itself only runs in `make e2e`.
//
//   - V4: no production binary (cmd/*) may pull in github.com/chromedp/* or any
//     internal/e2e package, however indirectly; and a `//go:build e2e` file may
//     exist only under internal/e2e/.
//   - V3: internal/e2e has no sleep (time.Sleep / chromedp.Sleep / time.After /
//     timers), does not switch off CSP (Page.setBypassCSP) or web security, and
//     the product's templates / CSS / JS never read data-testid.
//   - V8: `make e2e-serve` publishes only to the host's loopback.
//
// Each check is a function over a directory or a text, and is also run on a
// planted violation (a synthetic tree) that it must flag: a check that has never
// been seen to fail proves nothing.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

const (
	chromedpPrefix = "github.com/chromedp/"
	e2ePrefix      = modulePrefix + "internal/e2e"
)

// allImportsClosure is the import closure of the package at start (a
// module-qualified path): every import, standard, external and module-internal,
// of every module-internal package reached. Like importsOf it ignores build
// tags (a tagged file's imports count), and skips *_test.go.
func allImportsClosure(t *testing.T, root, start string) map[string]bool {
	t.Helper()
	all := map[string]bool{}
	seen := map[string]bool{}
	queue := []string{start}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		dir := filepath.Join(root, strings.TrimPrefix(pkg, modulePrefix))
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		for _, imp := range allImportsOf(t, dir) {
			all[imp] = true
			if strings.HasPrefix(imp, modulePrefix) {
				queue = append(queue, imp)
			}
		}
	}
	return all
}

// e2eLeaks lists the imports in cmd's closure that a production binary must not
// have.
func e2eLeaks(t *testing.T, root, cmd string) []string {
	t.Helper()
	var bad []string
	for imp := range allImportsClosure(t, root, modulePrefix+"cmd/"+cmd) {
		if strings.HasPrefix(imp, chromedpPrefix) || imp == e2ePrefix || strings.HasPrefix(imp, e2ePrefix+"/") {
			bad = append(bad, imp)
		}
	}
	sort.Strings(bad)
	return bad
}

func cmdNames(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestNoProductionBinaryImportsTheE2EHarness(t *testing.T) {
	root := repoRoot(t)
	names := cmdNames(t, root)
	// ADR-0031 V4 names six binaries. A seventh must be a deliberate decision, and
	// zero means the enumeration is broken (an empty loop would pass forever).
	if len(names) != 6 {
		t.Fatalf("cmd/ has %d binaries %v; ADR-0031 V4 checks the six production binaries — update this test with the new one", len(names), names)
	}
	for _, cmd := range names {
		t.Run(cmd, func(t *testing.T) {
			if bad := e2eLeaks(t, root, cmd); len(bad) > 0 {
				t.Fatalf("cmd/%s's import closure includes %v — a production binary must never import chromedp or internal/e2e (ADR-0031 V4: test-only code, and a browser-automation dependency, in a distroless image)", cmd, bad)
			}
		})
	}
}

// Planted violations: a direct import, a transitive one through an ordinary
// package, and the harness reached through two hops. Each must be flagged.
func TestE2ELeakDetector_CatchesPlantedImports(t *testing.T) {
	cases := []struct {
		name string
		// files: path (relative to root) -> source
		files map[string]string
		want  string
	}{
		{"chromedp imported directly by the binary", map[string]string{
			"cmd/fakebin/main.go": "package main\n\nimport _ \"github.com/chromedp/chromedp\"\n\nfunc main() {}\n",
		}, chromedpPrefix + "chromedp"},
		{"chromedp reached through an internal package", map[string]string{
			"cmd/fakebin/main.go":     "package main\n\nimport _ \"" + modulePrefix + "internal/fixture-a\"\n\nfunc main() {}\n",
			"internal/fixture-a/a.go": "package fixturea\n\nimport _ \"github.com/chromedp/cdproto/page\"\n",
		}, chromedpPrefix + "cdproto/page"},
		{"the harness reached through two hops", map[string]string{
			"cmd/fakebin/main.go":     "package main\n\nimport _ \"" + modulePrefix + "internal/fixture-a\"\n\nfunc main() {}\n",
			"internal/fixture-a/a.go": "package fixturea\n\nimport _ \"" + modulePrefix + "internal/fixture-b\"\n",
			"internal/fixture-b/b.go": "package fixtureb\n\nimport _ \"" + modulePrefix + "internal/e2e/harness\"\n",
		}, modulePrefix + "internal/e2e/harness"},
		{"a file under a build tag still counts", map[string]string{
			"cmd/fakebin/main.go": "package main\n\nimport _ \"" + modulePrefix + "internal/e2e\"\n\nfunc main() {}\n",
			"internal/e2e/x.go":   "//go:build e2e\n\npackage e2e\n",
		}, modulePrefix + "internal/e2e"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, src := range c.files {
				mustWriteGoFile(t, filepath.Dir(filepath.Join(root, rel)), filepath.Base(rel), src)
			}
			bad := e2eLeaks(t, root, "fakebin")
			found := false
			for _, b := range bad {
				if b == c.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("planted import of %s not flagged; leaks = %v", c.want, bad)
			}
		})
	}
	// ...and a clean binary is not flagged, so the detector is not red for everything.
	root := t.TempDir()
	mustWriteGoFile(t, filepath.Join(root, "cmd", "fakebin"), "main.go", "package main\n\nimport _ \"net/http\"\n\nfunc main() {}\n")
	if bad := e2eLeaks(t, root, "fakebin"); len(bad) != 0 {
		t.Errorf("a clean binary was flagged: %v", bad)
	}
}

var goBuildLine = regexp.MustCompile(`(?m)^//go:build\s+(.*)$`)
var e2eTag = regexp.MustCompile(`(^|[^A-Za-z0-9_])e2e($|[^A-Za-z0-9_])`)

// strayE2ETagFiles returns the .go files under root whose //go:build line names
// the e2e tag, other than those under internal/e2e/.
func strayE2ETagFiles(t *testing.T, root string) []string {
	t.Helper()
	var stray []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/e2e/") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Only the header counts: a //go:build line must precede the package clause.
		head := string(src)
		if i := strings.Index(head, "\npackage "); i >= 0 {
			head = head[:i]
		}
		for _, m := range goBuildLine.FindAllStringSubmatch(head, -1) {
			if e2eTag.MatchString(m[1]) {
				stray = append(stray, rel)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(stray)
	return stray
}

func TestE2EBuildTagLivesOnlyUnderInternalE2E(t *testing.T) {
	root := repoRoot(t)
	if stray := strayE2ETagFiles(t, root); len(stray) > 0 {
		t.Fatalf("files with //go:build e2e outside internal/e2e/: %v (ADR-0031 V4: the tag is how test-only code stays out of every build; it is allowed only there)", stray)
	}
	// The check does look at something: internal/e2e has tagged files, and the
	// tag is how Dockerfile.test and Dockerfile.e2e reach them.
	tagged := 0
	_ = filepath.WalkDir(filepath.Join(root, "internal", "e2e"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") {
			if src, rerr := os.ReadFile(p); rerr == nil && strings.HasPrefix(string(src), "//go:build e2e") {
				tagged++
			}
		}
		return nil
	})
	if tagged == 0 {
		t.Fatal("internal/e2e has no //go:build e2e file — the harness's browser code is not tagged, or this check is looking in the wrong place")
	}
	// `make test` compiles the tagged code.
	df, err := os.ReadFile(filepath.Join(root, "Dockerfile.test"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^RUN go vet -tags e2e \./\.\.\.$`).Match(df) {
		t.Error("Dockerfile.test must run `go vet -tags e2e ./...` so the e2e code keeps compiling (ADR-0031 V4)")
	}
}

func TestStrayE2ETagDetector_CatchesPlantedFile(t *testing.T) {
	root := t.TempDir()
	mustWriteGoFile(t, filepath.Join(root, "internal", "other"), "x.go", "//go:build e2e && linux\n\npackage other\n")
	mustWriteGoFile(t, filepath.Join(root, "internal", "other"), "y.go", "//go:build !windows\n\npackage other\n")
	mustWriteGoFile(t, filepath.Join(root, "internal", "other"), "z.go", "package other\n\n// //go:build e2e (a comment after the package clause)\n")
	mustWriteGoFile(t, filepath.Join(root, "internal", "e2e"), "ok.go", "//go:build e2e\n\npackage e2e\n")
	got := strayE2ETagFiles(t, root)
	if len(got) != 1 || got[0] != "internal/other/x.go" {
		t.Fatalf("stray tagged files = %v, want exactly [internal/other/x.go]", got)
	}
}

// --- V3 ---

var bannedSleepCalls = map[string]map[string]bool{
	"time":     {"Sleep": true, "After": true, "Tick": true, "NewTicker": true, "NewTimer": true, "AfterFunc": true},
	"chromedp": {"Sleep": true},
}

// bannedBrowserIdents are chromedp / CDP names that switch off a check or
// rewrite what the browser would see by a route the Chromium flag allowlist
// does not cover: a trust or proxy switch set through chromedp's own options,
// the escape hatch that edits the command line afterwards, chromedp's default
// option set (a dozen unreviewed switches), a connection to some other
// browser, CDP's certificate-error override, and request interception (which
// can answer in place of the server). The live command line is checked as well
// (harness.CheckArgv), but a CDP call leaves no trace there.
var bannedBrowserIdents = map[string]string{
	"IgnoreCertErrors":            "switches certificate checking off",
	"ProxyServer":                 "sends the browser's traffic elsewhere",
	"ModifyCmdFunc":               "edits the command line after the allowlist was checked",
	"DefaultExecAllocatorOptions": "brings switches nobody reviewed",
	"NewRemoteAllocator":          "drives a browser the harness did not launch with its allowlist",
	"SetIgnoreCertificateErrors":  "Security.setIgnoreCertificateErrors switches certificate checking off",
	"SetRequestInterception":      "can answer a request in place of the server",
	"FulfillRequest":              "Fetch.fulfillRequest answers a request in place of the server",
	"ContinueResponse":            "Fetch.continueResponse rewrites a response",
}

// bannedBrowserImports are CDP domains the harness has no use for: Fetch (answers
// or rewrites requests and responses) and Security (certificate overrides).
var bannedBrowserImports = []string{
	"github.com/chromedp/cdproto/fetch",
	"github.com/chromedp/cdproto/security",
}

// e2eSourceViolations parses every .go file under dir (testdata excluded) and
// reports a sleep or timer call, any identifier or string that names
// Page.setBypassCSP, a banned chromedp / CDP name or import (see
// bannedBrowserIdents), and a string literal that is a banned Chromium switch
// (outside the files that define and test the ban list).
func e2eSourceViolations(t *testing.T, dir string, banFiles ...string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		report := func(pos token.Pos, what string) {
			out = append(out, rel+":"+strconv.Itoa(fset.Position(pos).Line)+": "+what)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && bannedSleepCalls[id.Name][x.Sel.Name] {
					report(x.Pos(), id.Name+"."+x.Sel.Name+" (wait on the proxy's log or a DOM predicate, never on a clock)")
				}
			case *ast.Ident:
				if strings.Contains(strings.ToLower(x.Name), "bypasscsp") {
					report(x.Pos(), "identifier "+x.Name+" (Page.setBypassCSP is forbidden)")
				}
				if why, bad := bannedBrowserIdents[x.Name]; bad {
					report(x.Pos(), "identifier "+x.Name+" ("+why+")")
				}
			case *ast.ImportSpec:
				ip, _ := strconv.Unquote(x.Path.Value)
				for _, b := range bannedBrowserImports {
					if ip == b || strings.HasPrefix(ip, b+"/") {
						report(x.Pos(), "import "+x.Path.Value+" (a CDP domain that rewrites requests, responses or certificate trust)")
					}
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING {
					return true
				}
				s, _ := strconv.Unquote(x.Value)
				if strings.Contains(strings.ToLower(s), "bypasscsp") {
					report(x.Pos(), "string "+x.Value+" (Page.setBypassCSP is forbidden)")
				}
				for _, cdp := range []string{"Security.setIgnoreCertificateErrors", "Fetch.", "Network.setRequestInterception"} {
					if strings.Contains(s, cdp) {
						report(x.Pos(), "string "+x.Value+" names the CDP method "+cdp+" (rewrites what the browser sees)")
					}
				}
				if !slices.Contains(banFiles, filepath.Base(path)) {
					for _, flag := range harness.BannedChromiumFlags {
						if s == flag || s == "--"+flag || strings.HasPrefix(s, "--"+flag+"=") {
							report(x.Pos(), "string "+x.Value+" names the banned Chromium switch --"+flag)
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestE2ESourceHasNoSleepBypassOrBannedFlag(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "e2e")
	if v := e2eSourceViolations(t, dir, "chromeflags.go", "chromeflags_test.go"); len(v) > 0 {
		t.Fatalf("internal/e2e breaks ADR-0031 V3:\n  %s", strings.Join(v, "\n  "))
	}
}

func TestE2ESourceDetector_CatchesPlantedViolations(t *testing.T) {
	cases := map[string]string{
		"time.Sleep":           "package x\n\nimport \"time\"\n\nfunc f() { time.Sleep(time.Second) }\n",
		"time.After":           "package x\n\nimport \"time\"\n\nfunc f() { <-time.After(time.Second) }\n",
		"time.NewTicker":       "package x\n\nimport \"time\"\n\nfunc f() { _ = time.NewTicker(time.Second) }\n",
		"chromedp.Sleep":       "package x\n\nimport \"github.com/chromedp/chromedp\"\n\nvar _ = chromedp.Sleep\n",
		"setBypassCSP call":    "package x\n\nfunc f(p interface{ SetBypassCSP(bool) }) { p.SetBypassCSP(true) }\n",
		"setBypassCSP literal": "package x\n\nvar m = \"Page.setBypassCSP\"\n",
		"disable-web-security": "package x\n\nvar f = \"--disable-web-security\"\n",
		// V3 review (LOW-1): routes to the same ends that the flag allowlist and a
		// string match on a switch name do not see.
		"chromedp.IgnoreCertErrors":            "package x\n\nimport \"github.com/chromedp/chromedp\"\n\nvar _ = chromedp.IgnoreCertErrors\n",
		"chromedp.ProxyServer":                 "package x\n\nimport \"github.com/chromedp/chromedp\"\n\nvar _ = chromedp.ProxyServer(\"http://x\")\n",
		"chromedp.ModifyCmdFunc":               "package x\n\nimport \"github.com/chromedp/chromedp\"\n\nvar _ = chromedp.ModifyCmdFunc\n",
		"chromedp.DefaultExecAllocatorOptions": "package x\n\nimport \"github.com/chromedp/chromedp\"\n\nvar _ = chromedp.DefaultExecAllocatorOptions\n",
		"chromedp.NewRemoteAllocator":          "package x\n\nimport \"github.com/chromedp/chromedp\"\n\nvar _ = chromedp.NewRemoteAllocator\n",
		"security.SetIgnoreCertificateErrors":  "package x\n\nfunc f(security interface{ SetIgnoreCertificateErrors(bool) }) { security.SetIgnoreCertificateErrors(true) }\n",
		"fetch import":                         "package x\n\nimport _ \"github.com/chromedp/cdproto/fetch\"\n",
		"security import":                      "package x\n\nimport _ \"github.com/chromedp/cdproto/security\"\n",
		"fetch.FulfillRequest":                 "package x\n\nfunc f(fetch interface{ FulfillRequest(string) }) { fetch.FulfillRequest(\"1\") }\n",
		"CDP method as a string":               "package x\n\nvar m = \"Fetch.fulfillRequest\"\n",
		"Security CDP method as a string":      "package x\n\nvar m = \"Security.setIgnoreCertificateErrors\"\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWriteGoFile(t, dir, "x.go", src)
			if v := e2eSourceViolations(t, dir, "chromeflags.go", "chromeflags_test.go"); len(v) == 0 {
				t.Fatalf("planted %s not flagged", name)
			}
		})
	}
	dir := t.TempDir()
	mustWriteGoFile(t, dir, "ok.go", "package x\n\nimport \"time\"\n\nconst limit = 5 * time.Second\n")
	if v := e2eSourceViolations(t, dir, "chromeflags.go", "chromeflags_test.go"); len(v) != 0 {
		t.Errorf("a time.Duration constant was flagged: %v", v)
	}
}

var testIDRead = regexp.MustCompile(`\[\s*data-testid|dataset\.testid|getAttribute\(\s*['"]data-testid|querySelector[A-Za-z]*\([^)]*data-testid`)

// testIDReaders lists the product files (templates, CSS, JS) under dir that read
// data-testid. Writing the attribute in markup is allowed (ADR-0031 D3: added
// only when an id or data attribute the page already uses is not enough); the
// product reading it is not — a selector the tests depend on must not become one
// the product depends on.
func testIDReaders(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".tmpl", ".html", ".css", ".js":
		default:
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if testIDRead.Match(src) {
			rel, _ := filepath.Rel(dir, path)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProductDoesNotReadDataTestID(t *testing.T) {
	root := repoRoot(t)
	view := filepath.Join(root, "internal", "scoreboard", "view")
	n := 0
	_ = filepath.WalkDir(filepath.Join(view, "templates"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if n == 0 {
		t.Fatal("no template files found under internal/scoreboard/view/templates — the scan is looking in the wrong place")
	}
	for _, sub := range []string{"templates", "static"} {
		if bad := testIDReaders(t, filepath.Join(view, sub)); len(bad) > 0 {
			t.Errorf("product files in view/%s read data-testid: %v (ADR-0031 V3)", sub, bad)
		}
	}
}

func TestTestIDDetector_CatchesPlantedReaders(t *testing.T) {
	cases := map[string]struct {
		file, src string
		flagged   bool
	}{
		"css attribute selector": {"a.css", `[data-testid="x"] { color: red }`, true},
		"js dataset":             {"a.tmpl", `<script>el.dataset.testid</script>`, true},
		"js getAttribute":        {"a.js", `el.getAttribute('data-testid')`, true},
		"js querySelector":       {"a.tmpl", `<script>document.querySelector('[data-testid=go]')</script>`, true},
		"markup only":            {"a.tmpl", `<button data-testid="reset">x</button>`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.src), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := len(testIDReaders(t, dir)) == 1; got != c.flagged {
				t.Fatalf("flagged = %v, want %v", got, c.flagged)
			}
		})
	}
}

// --- V8 (the part that is a property of the Makefile) ---

var publishFlag = regexp.MustCompile(`(?:^|\s)(?:-p|--publish|-P|--publish-all)(?:\s+|=)?(\S*)`)

// hostNetworkFlag matches --network host / --network=host (and the --net
// spellings). Host networking makes the container's every listener a listener
// of the host itself, on every interface: the -p 127.0.0.1 restriction would be
// moot (docker ignores -p there), so it is as bad as publishing on 0.0.0.0.
var hostNetworkFlag = regexp.MustCompile(`(?:^|\s)--net(?:work)?(?:\s+|=)["']?host["']?(?:\s|$)`)

// e2eServePublishViolations checks the e2e-serve recipe's docker run: every
// published port is bound to 127.0.0.1, there is at least one, and none is
// -P / --publish-all (which publishes every EXPOSEd port on all interfaces).
func e2eServePublishViolations(makefile string) []string {
	i := strings.Index(makefile, "\ne2e-serve:")
	if i < 0 {
		return []string{"no e2e-serve target"}
	}
	recipe := makefile[i+1:]
	// the recipe ends at the next target line (a line that starts a name:).
	if j := regexp.MustCompile(`(?m)^[A-Za-z0-9_.-]+:`).FindAllStringIndex(recipe, 2); len(j) == 2 {
		recipe = recipe[:j[1][0]]
	}
	recipe = strings.ReplaceAll(recipe, "\\\n", " ")
	var out []string
	if hostNetworkFlag.MatchString(recipe) {
		out = append(out, "runs with --network host (every listener of the container is then a listener of the host, whatever -p says)")
	}
	n := 0
	for _, m := range publishFlag.FindAllStringSubmatch(recipe, -1) {
		n++
		if !strings.HasPrefix(m[1], "127.0.0.1:") {
			out = append(out, "publishes "+strconv.Quote(m[1])+" (want 127.0.0.1:<port>:<port>)")
		}
	}
	if n == 0 {
		out = append(out, "publishes no port at all (the target would serve nothing)")
	}
	return out
}

func TestE2EServePublishesOnlyToHostLoopback(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if v := e2eServePublishViolations(string(mk)); len(v) > 0 {
		t.Fatalf("Makefile e2e-serve: %v (ADR-0031 V8)", v)
	}
}

func TestE2EServePublishDetector_CatchesPlantedViolations(t *testing.T) {
	good := "e2e-serve:\n\tdocker run --rm \\\n\t  -p 127.0.0.1:$(E2E_PORT):$(E2E_PORT) \\\n\t  img\n\ncheck:\n\ttrue\n"
	if v := e2eServePublishViolations("x:\n\ttrue\n\n" + good); len(v) != 0 {
		t.Fatalf("the good recipe was flagged: %v", v)
	}
	for name, mk := range map[string]string{
		"all interfaces":   strings.Replace(good, "-p 127.0.0.1:", "-p ", 1),
		"0.0.0.0":          strings.Replace(good, "127.0.0.1:", "0.0.0.0:", 1),
		"publish-all":      strings.Replace(good, "-p 127.0.0.1:$(E2E_PORT):$(E2E_PORT)", "-P", 1),
		"long form":        strings.Replace(good, "-p 127.0.0.1:", "--publish 8787:", 1),
		"second, open one": strings.Replace(good, "img", "-p 9000:9000 img", 1),
		"no publish":       strings.Replace(good, "-p 127.0.0.1:$(E2E_PORT):$(E2E_PORT)", "", 1),
		// V8 review (LOW-2): host networking is as open as 0.0.0.0, with -p still in place.
		"--network host":                      strings.Replace(good, "--rm", "--rm --network host", 1),
		"--network=host":                      strings.Replace(good, "--rm", "--rm --network=host", 1),
		"--net=host":                          strings.Replace(good, "--rm", "--rm --net=host", 1),
		"--network host quoted":               strings.Replace(good, "--rm", `--rm --network "host"`, 1),
		"--network host at the end of a line": strings.Replace(good, "img", "--network host \\\n\t  img", 1),
	} {
		if v := e2eServePublishViolations(mk); len(v) == 0 {
			t.Errorf("planted %q not flagged", name)
		}
	}
}
