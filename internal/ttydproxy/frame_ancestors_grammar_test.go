package ttydproxy_test

// app#520 / ADR-0044: the FRAME_ANCESTORS grammar. The one definition is the Go constant
// ttydproxy.FrameAncestorsPattern (and FrameAncestorsMaxLen); New refuses to start on a
// value outside it. charts/ctf-user/deploy-user.sh holds the same text as
// FRAME_ANCESTORS_PATTERN, and testdata/frame-ancestors-cases.tsv as its `# pattern: `
// header; this file holds the three equal, the host part equal to DNS_SUFFIX_PATTERN's
// body (the `--app-host` grammar), and runs every row through the constant and through
// New. scripts/check-deploy-user-ids.sh runs the same rows through deploy-user.sh itself.

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/casetable"
	"github.com/Qfour/falco-ctf-app/internal/ttydproxy"
)

const casesFile = "frame-ancestors-cases.tsv"

func readFile(t *testing.T, path ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newWith(v string) error {
	_, err := ttydproxy.New("http://127.0.0.1:7682", v, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return err
}

// The Go constant, the shell literal and the table's header are one text, and the host
// part of it is the `--app-host` grammar: a change to one alone is red here.
func TestFrameAncestorsGrammar_OneDefinition(t *testing.T) {
	script := readFile(t, "..", "..", "charts", "ctf-user", "deploy-user.sh")
	header, ok := casetable.Header(readFile(t, "testdata", casesFile))
	if !ok {
		t.Fatalf("%s line 1 must be %q followed by the regex", casesFile, casetable.HeaderPrefix)
	}
	if header != ttydproxy.FrameAncestorsPattern {
		t.Errorf("%s header = %q, want ttydproxy.FrameAncestorsPattern %q", casesFile, header, ttydproxy.FrameAncestorsPattern)
	}
	shell, ok := casetable.ShellAssignDouble(script, "FRAME_ANCESTORS_PATTERN")
	if !ok {
		t.Fatal(`deploy-user.sh must define FRAME_ANCESTORS_PATTERN="..." exactly once on its own line (double quoted: the grammar holds a single quote; nothing bash would expand)`)
	}
	if shell != ttydproxy.FrameAncestorsPattern {
		t.Errorf("deploy-user.sh FRAME_ANCESTORS_PATTERN = %q, want ttydproxy.FrameAncestorsPattern %q", shell, ttydproxy.FrameAncestorsPattern)
	}

	// The host part: --app-host's DNS_SUFFIX_PATTERN, between its anchors.
	dns, ok := casetable.ShellAssign(script, "DNS_SUFFIX_PATTERN")
	if !ok {
		t.Fatal("deploy-user.sh must define DNS_SUFFIX_PATTERN='...' exactly once on its own line")
	}
	body, okPrefix := strings.CutPrefix(dns, "^")
	body, okSuffix := strings.CutSuffix(body, "$")
	if !okPrefix || !okSuffix {
		t.Fatalf("DNS_SUFFIX_PATTERN %q is not anchored ^...$: the host part cannot be cut out of it", dns)
	}
	if want := "^('none'|https://" + body + ")$"; ttydproxy.FrameAncestorsPattern != want {
		t.Errorf("FrameAncestorsPattern = %q, want 'none' or https:// and DNS_SUFFIX_PATTERN's body: %q", ttydproxy.FrameAncestorsPattern, want)
	}

	// The bound: `https://` and DNS_SUFFIX_MAX_LEN's 253, in one literal beside the pattern.
	maxLit, ok := casetable.ShellAssign(script, "FRAME_ANCESTORS_MAX_LEN")
	if !ok {
		t.Fatal("deploy-user.sh must define FRAME_ANCESTORS_MAX_LEN='...' exactly once on its own line")
	}
	if maxLit != "261" || ttydproxy.FrameAncestorsMaxLen != 261 {
		t.Errorf("FRAME_ANCESTORS_MAX_LEN = %q, FrameAncestorsMaxLen = %d, want 261 (len(\"https://\") + 253)", maxLit, ttydproxy.FrameAncestorsMaxLen)
	}
	if dnsMax, _ := casetable.ShellAssign(script, "DNS_SUFFIX_MAX_LEN"); dnsMax != "253" {
		t.Errorf("DNS_SUFFIX_MAX_LEN = %q, want 253: FrameAncestorsMaxLen is len(\"https://\") + it", dnsMax)
	}
}

// Every row of the shared table, through the constant (plus the length bound) and
// through New: an accepted value starts, a rejected one is an error.
func TestFrameAncestorsGrammar_SharedCaseTable(t *testing.T) {
	re := regexp.MustCompile(ttydproxy.FrameAncestorsPattern)
	rows, err := casetable.Read(filepath.Join("testdata", casesFile))
	if err != nil {
		t.Fatal(err)
	}
	accepted, rejected := 0, 0
	for _, r := range rows {
		if r.Accept {
			accepted++
		} else {
			rejected++
		}
		got := re.MatchString(r.Input) && len(r.Input) <= ttydproxy.FrameAncestorsMaxLen
		if got != r.Accept {
			t.Errorf("%s:%d: %q is accepted by the pattern = %v, want %v", casesFile, r.Line, r.Input, got, r.Accept)
		}
		if err := newWith(r.Input); (err == nil) != r.Accept {
			t.Errorf("%s:%d: New(%q) error = %v, want an error exactly when the row is a reject", casesFile, r.Line, r.Input, err)
		}
	}
	if len(rows) < 70 || accepted < 10 || rejected < 50 {
		t.Fatalf("%s has %d rows (%d accept / %d reject): the table was truncated or misread", casesFile, len(rows), accepted, rejected)
	}
}

// What the chart ships with, and what New defaults to, must pass the grammar: a grammar
// tightened past them is red here, not at a stand-up.
func TestFrameAncestorsGrammar_DefaultsAreAccepted(t *testing.T) {
	values := readFile(t, "..", "..", "charts", "ctf-user", "values.yaml")
	m := regexp.MustCompile(`(?m)^  frameAncestors:\s*"([^"\n]*)"\s*$`).FindStringSubmatch(values)
	if m == nil {
		t.Fatal(`values.yaml has no 2-space-indented frameAncestors: "..." line (ttyd.frameAncestors): the test's reader is stale`)
	}
	if m[1] != "'none'" {
		t.Errorf("chart default ttyd.frameAncestors = %q, want 'none' (fail-safe: nobody may frame ttyd)", m[1])
	}
	if err := newWith(m[1]); err != nil {
		t.Errorf("chart default %q is refused: %v", m[1], err)
	}
	if err := newWith(""); err != nil {
		t.Errorf("an empty FRAME_ANCESTORS must stay the 'none' default, got: %v", err)
	}
}
