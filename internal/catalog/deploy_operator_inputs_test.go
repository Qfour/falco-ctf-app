package catalog_test

// app#510 (#507 review-5x R1#1): the operator inputs of charts/ctf-user/deploy-user.sh
// other than the seat and the challenge id: --dns-suffix, FALCO_CTF_REGISTRY,
// FALCO_CTF_IMAGE_TAG and --api-server-cidr. Each is checked against a closed grammar
// before any kubectl / helm call and passed to helm with --set-string.
//
// None of the four has a Go definition (an operator input is read by deploy-user.sh
// only, and platform holds no grammar: it derives the registry and the tag from its env
// file and hands them to this script), so the shell literal IS the definition. This test
// holds it equal to the `# pattern: ` header of the shared case table (the form
// scenario_name_test.go uses), runs every row through the literal, and requires the
// values the chart ships with to be accepted. scripts/check-deploy-user-ids.sh runs the
// same rows through deploy-user.sh itself.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
)

// dnsSuffixMaxLen is RFC 1123's limit on a whole name. A regex cannot count the whole,
// so deploy-user.sh checks DNS_SUFFIX_MAX_LEN after DNS_SUFFIX_PATTERN; this constant
// is the pin, and the table's rows hold the behaviour at 253 / 254.
const dnsSuffixMaxLen = 253

type operatorGrammar struct {
	table     string // file under testdata/
	shellVar  string // the NAME='...' assignment in deploy-user.sh
	maxLen    int    // 0 = no bound beyond the pattern
	minRows   int
	minAccept int
	minReject int
}

var operatorGrammars = []operatorGrammar{
	{"dns-suffix-cases.tsv", "DNS_SUFFIX_PATTERN", dnsSuffixMaxLen, 50, 15, 30},
	{"image-registry-cases.tsv", "REGISTRY_PATTERN", 0, 80, 14, 60},
	{"image-tag-cases.tsv", "IMAGE_TAG_PATTERN", 0, 50, 15, 25},
	{"api-server-cidr-cases.tsv", "API_SERVER_CIDR_PATTERN", 0, 65, 15, 45},
}

func readDeployUser(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "charts", "ctf-user", "deploy-user.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func shellPattern(t *testing.T, script, name string) *regexp.Regexp {
	t.Helper()
	lit, ok := casetable.ShellAssign(script, name)
	if !ok {
		t.Fatalf("deploy-user.sh must define %s='...' exactly once on its own line", name)
	}
	return regexp.MustCompile(lit)
}

func TestDeployUserOperatorInputs_SharedCaseTables(t *testing.T) {
	script := readDeployUser(t)
	for _, g := range operatorGrammars {
		t.Run(g.table, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", g.table))
			if err != nil {
				t.Fatal(err)
			}
			header, ok := casetable.Header(string(raw))
			if !ok {
				t.Fatalf("%s line 1 must be %q followed by the regex", g.table, casetable.HeaderPrefix)
			}
			shell, ok := casetable.ShellAssign(script, g.shellVar)
			if !ok {
				t.Fatalf("deploy-user.sh must define %s='...' exactly once on its own line", g.shellVar)
			}
			if shell != header {
				t.Fatalf("deploy-user.sh %s = %q, want the table's header pattern %q", g.shellVar, shell, header)
			}
			re := regexp.MustCompile(shell)
			rows, err := casetable.Parse(g.table, string(raw))
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) < g.minRows {
				t.Fatalf("%s has %d rows, want at least %d: the table was truncated or misread", g.table, len(rows), g.minRows)
			}
			accepted, rejected := 0, 0
			for _, r := range rows {
				if r.Accept {
					accepted++
				} else {
					rejected++
				}
				got := re.MatchString(r.Input) && (g.maxLen == 0 || len(r.Input) <= g.maxLen)
				if got != r.Accept {
					t.Errorf("%s:%d: %q is accepted = %v, want %v", g.table, r.Line, r.Input, got, r.Accept)
				}
			}
			if accepted < g.minAccept || rejected < g.minReject {
				t.Fatalf("%s has %d accept / %d reject rows: too few of one kind to hold the grammar", g.table, accepted, rejected)
			}
		})
	}
}

// DNS_SUFFIX_MAX_LEN is a shell literal beside the pattern: pin its text to RFC 1123's
// 253, so a loosened bound is red even where no row sits at the new edge.
func TestDeployUserDNSSuffixMaxLenIs253(t *testing.T) {
	got, ok := casetable.ShellAssign(readDeployUser(t), "DNS_SUFFIX_MAX_LEN")
	if !ok {
		t.Fatal("deploy-user.sh must define DNS_SUFFIX_MAX_LEN='...' exactly once on its own line")
	}
	if got != "253" {
		t.Errorf("deploy-user.sh DNS_SUFFIX_MAX_LEN = %q, want %q (RFC 1123)", got, "253")
	}
}

// What the chart ships with must pass the grammar deploy-user.sh enforces: a grammar
// tightened past a default is red here, not at a stand-up that passes the default
// through. (Prod's real values are in the private repo and are not read here; the case
// tables carry synthetic ones of the same shape.)
func TestDeployUserOperatorInputs_ChartDefaultsAreAccepted(t *testing.T) {
	script := readDeployUser(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "charts", "ctf-user", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	values := string(raw)

	dns := shellPattern(t, script, "DNS_SUFFIX_PATTERN")
	m := regexp.MustCompile(`(?m)^dnsSuffix:\s*"([^"\n]*)"\s*$`).FindStringSubmatch(values)
	if m == nil {
		t.Fatal("values.yaml has no top-level dnsSuffix: \"...\" line: the test's reader is stale")
	}
	if !dns.MatchString(m[1]) || len(m[1]) > dnsSuffixMaxLen {
		t.Errorf("chart default dnsSuffix %q does not pass deploy-user.sh's --dns-suffix grammar", m[1])
	}

	reg := shellPattern(t, script, "REGISTRY_PATTERN")
	tag := shellPattern(t, script, "IMAGE_TAG_PATTERN")
	repos := regexp.MustCompile(`(?m)^\s+repository:\s*(\S+)/(ttyd|ttyd-proxy|challenge)\s*$`).FindAllStringSubmatch(values, -1)
	if len(repos) != 3 {
		t.Fatalf("values.yaml has %d `repository: <registry>/<image>` lines for ttyd / ttyd-proxy / challenge, want 3: the test's reader is stale", len(repos))
	}
	for _, r := range repos {
		if !reg.MatchString(r[1]) {
			t.Errorf("chart default registry %q (of %s) does not pass deploy-user.sh's FALCO_CTF_REGISTRY grammar", r[1], r[2])
		}
	}
	tags := regexp.MustCompile(`(?m)^\s+tag:\s*(\S+)\s*$`).FindAllStringSubmatch(values, -1)
	if len(tags) != 3 {
		t.Fatalf("values.yaml has %d `tag:` lines, want 3 (ttyd, ttyd-proxy, challenge): the test's reader is stale", len(tags))
	}
	for _, r := range tags {
		if !tag.MatchString(strings.Trim(r[1], `"'`)) {
			t.Errorf("chart default image tag %q does not pass deploy-user.sh's FALCO_CTF_IMAGE_TAG grammar", r[1])
		}
	}
}

// FALCO_CTF_REGISTRY must end in `falco-ctf`: the three images are `${REGISTRY}/<name>`, and
// the scoreboard ingest ignores a Falco event whose container.image.repository does not
// contain `falco-ctf/challenge`, so a registry that fails the filter deploys a workspace
// whose detections are silently never scored. Two pins: the ingest still filters on that
// substring (if it changes, this grammar is stale), and every accepted registry gives a
// challenge repository the filter accepts.
func TestDeployUserRegistryGrammarMatchesTheIngestFilter(t *testing.T) {
	ingest, err := os.ReadFile(filepath.Join("..", "scoreboard", "ingest", "ingest.go"))
	if err != nil {
		t.Fatal(err)
	}
	const filter = `strings.Contains(imageRepo, "falco-ctf/challenge")`
	if !strings.Contains(string(ingest), filter) {
		t.Fatalf("internal/scoreboard/ingest/ingest.go no longer has %s: deploy-user.sh's REGISTRY_PATTERN (last component falco-ctf) is stale, update both", filter)
	}
	rows, err := casetable.Read(filepath.Join("testdata", "image-registry-cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, r := range rows {
		if !r.Accept {
			continue
		}
		checked++
		if repo := r.Input + "/challenge"; !strings.Contains(repo, "falco-ctf/challenge") {
			t.Errorf("image-registry-cases.tsv:%d: accepted %q gives the challenge repository %q, which the scoreboard ingest would ignore", r.Line, r.Input, repo)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d accept rows checked: the table was misread", checked)
	}
}
