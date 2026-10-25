package ingressparity

// ADR-0042 (app#480): the seat grammar is the set of names a workspace can be
// DEPLOYED with. A seat becomes the Helm release name (deploy-user.sh passes it
// as the release), the `ctf-<seat>` namespace, label values and the first label
// of the workspace host. This test renders charts/ctf-user the way the deploy
// does for the edges of the grammar and checks every name the chart builds from
// the seat with the Kubernetes validators, and shows that just outside the
// grammar Helm itself refuses. If the deploy starts building a different (e.g.
// prefixed) name from the seat, this goes red and the grammar is to be revisited
// (ADR-0042 Signpost 1).
//
// What this test does NOT hold: that the release name is the seat and the
// namespace is `ctf-<seat>`. It calls `helm template <seat>` itself, so it only
// sees the names the CHART builds. That derivation is pinned by V2
// (scripts/check-seat-grammar.sh), on deploy-user.sh's recorded helm / kubectl
// calls; this test is written on that premise.
//
// Like ADR-0034 V12 (authurl_test.go) it FAILS when helm is missing: a skipped
// derivation test would be a silently-green "every seat can be deployed".

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// helmTemplateCtfUser runs `helm template <release> charts/ctf-user <args...>` from the
// repo root and returns helm's combined output. helm missing is a failure, not a skip.
func helmTemplateCtfUser(t *testing.T, release string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm is not on PATH: the seat derivation test renders charts/ctf-user and may not be skipped (Dockerfile.test installs helm; a local run needs it too)")
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("helm", append([]string{"template", release, filepath.Join("charts", "ctf-user")}, args...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// renderSeat runs `helm template <seat> charts/ctf-user --set-string username=<seat>`:
// release name = seat, as in charts/ctf-user/deploy-user.sh. It returns the
// decoded manifests and helm's combined output.
func renderSeat(t *testing.T, seat string) ([]map[string]any, string, error) {
	t.Helper()
	out, err := helmTemplateCtfUser(t, seat, "--set-string", "username="+seat, "--set", "dnsSuffix=ctf.example.invalid")
	if err != nil {
		return nil, out, err
	}
	dec := yaml.NewDecoder(strings.NewReader(out))
	var docs []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("seat %q: parse helm output: %v", seat, err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs, out, nil
}

// seatDerived is every name the rendered chart builds from the seat.
type seatDerived struct {
	namespaces  []string // metadata.namespace of every object
	labelValues []string // every label / matchLabels value that is a string
	notStrings  []string // labels whose value YAML read as a number / bool / null (Kubernetes refuses them)
	hosts       []string // Ingress rule hosts and tls hosts
}

func collectSeatDerived(docs []map[string]any) seatDerived {
	var d seatDerived
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if (key == "labels" || key == "matchLabels") && k != "" {
					if s, ok := val.(string); ok {
						d.labelValues = append(d.labelValues, s)
					} else {
						d.notStrings = append(d.notStrings, fmt.Sprintf("%s=%v (%T)", k, val, val))
					}
					continue
				}
				if key == "metadata" && k == "namespace" {
					if s, ok := val.(string); ok {
						d.namespaces = append(d.namespaces, s)
						continue
					}
				}
				if k == "host" {
					if s, ok := val.(string); ok {
						d.hosts = append(d.hosts, s)
						continue
					}
				}
				if k == "hosts" {
					if l, ok := val.([]any); ok {
						for _, h := range l {
							if s, ok := h.(string); ok {
								d.hosts = append(d.hosts, s)
							}
						}
						continue
					}
				}
				walk(k, val)
			}
		case []any:
			for _, e := range x {
				walk(key, e)
			}
		}
	}
	for _, doc := range docs {
		walk("", doc)
	}
	return d
}

// seatViolations returns what is wrong with the names derived from seat.
func seatViolations(seat string, d seatDerived) []string {
	var v []string
	ns := "ctf-" + seat // also created by deploy-user.sh with kubectl, not in the chart
	for _, errs := range [][]string{validation.IsDNS1123Label(ns)} {
		for _, e := range errs {
			v = append(v, "namespace "+ns+": "+e)
		}
	}
	for _, n := range d.namespaces {
		if n != ns {
			v = append(v, "an object is in namespace "+n+", want "+ns)
		}
		for _, e := range validation.IsDNS1123Label(n) {
			v = append(v, "namespace "+n+": "+e)
		}
	}
	for _, n := range d.notStrings {
		v = append(v, "label not a string: "+n+" (the chart must quote it)")
	}
	for _, l := range d.labelValues {
		for _, e := range validation.IsValidLabelValue(l) {
			v = append(v, "label value "+l+": "+e)
		}
	}
	for _, h := range d.hosts {
		first, _, _ := strings.Cut(h, ".")
		for _, e := range validation.IsDNS1123Label(first) {
			v = append(v, "host "+h+" first label: "+e)
		}
		for _, e := range validation.IsDNS1123Subdomain(h) {
			v = append(v, "host "+h+": "+e)
		}
	}
	return v
}

func TestSeatGrammar_EverySeatInTheGrammarRendersWithValidNames(t *testing.T) {
	for _, seat := range []string{
		"a", "0", "ab", "a-b", "a--b", "user1", "test1", "1a",
		// look like a number / a bool / null to YAML: they must stay strings
		"123", "1e3", "true", "null",
		"a" + strings.Repeat("b", 51), // 52
		"a" + strings.Repeat("b", 52), // 53: the longest
		"a" + strings.Repeat("-", 51) + "b",
	} {
		t.Run(seat, func(t *testing.T) {
			if !identity.ValidSeat(seat) {
				t.Fatalf("%q is not a seat by identity.SeatPattern: the case list and the grammar disagree", seat)
			}
			docs, out, err := renderSeat(t, seat)
			if err != nil {
				t.Fatalf("helm template for the seat %q failed although it is in the grammar: %v\n%s", seat, err, out)
			}
			d := collectSeatDerived(docs)
			// Non-vacuous: the seat really flows into a namespace, a label value
			// and the host's first label, so the checks below looked at it.
			if len(d.namespaces) == 0 || len(d.hosts) == 0 {
				t.Fatalf("extracted %d namespace(s) and %d host(s) from the render: the extraction is broken, not clean", len(d.namespaces), len(d.hosts))
			}
			found := false
			for _, l := range d.labelValues {
				if l == seat {
					found = true
				}
			}
			if !found {
				t.Fatalf("no label value equals the seat %q: the render does not carry it where this test looks", seat)
			}
			sawHost := false
			for _, h := range d.hosts {
				if strings.HasPrefix(h, seat+".") {
					sawHost = true
				}
			}
			if !sawHost {
				t.Fatalf("no host starts with %q.: the workspace host is not built from the seat as this test assumes (hosts %v)", seat, d.hosts)
			}
			for _, viol := range seatViolations(seat, d) {
				t.Errorf("seat %q: %s", seat, viol)
			}
		})
	}
}

// ADR-0042 C4: the chart guards the type of the seat itself. Helm's `--set` types
// the value (`0` `123` an integer, `true` a boolean, `null` removes the key), and a
// namespace `ctf-<nil>` or a label written as a bare scalar is a render that is
// either refused by Kubernetes or silently wrong. deploy-user.sh passes
// --set-string; any other caller (helm template, a values file) gets the chart's
// `fail`, which names the way out. The same value through --set-string is a seat.
func TestSeatGuard_AUsernameThatIsNotAStringIsRefusedByTheChart(t *testing.T) {
	for _, c := range []struct{ name, set, kind string }{
		{"integer 0", "username=0", "int64"},
		{"integer 123", "username=123", "int64"},
		{"boolean", "username=true", "bool"},
		{"null", "username=null", "invalid"},
		{"empty", "username=", "string"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := helmTemplateCtfUser(t, "x", "--set", c.set, "--set", "dnsSuffix=ctf.example.invalid")
			if err == nil {
				t.Fatalf("helm template --set %s rendered (%d bytes): the chart does not guard the type of username", c.set, len(out))
			}
			for _, want := range []string{"username must be a non-empty string", "got " + c.kind, "--set-string", "ADR-0042 C4"} {
				if !strings.Contains(out, want) {
					t.Errorf("helm refused --set %s, but the message lacks %q: %s", c.set, want, out)
				}
			}
		})
	}
	// A values file types the same way (YAML: 123 is an int, 1e3 a float, true a bool).
	for name, yamlValue := range map[string]string{"values file int": "123", "values file float": "1e3", "values file bool": "true"} {
		t.Run(name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "values.yaml")
			if err := os.WriteFile(f, []byte("username: "+yamlValue+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := helmTemplateCtfUser(t, "x", "-f", f, "--set", "dnsSuffix=ctf.example.invalid")
			if err == nil || !strings.Contains(out, "username must be a non-empty string") {
				t.Fatalf("username: %s in a values file was not refused by the chart: err=%v (%d bytes of output)", yamlValue, err, len(out))
			}
		})
	}
	// The same values as strings render: the guard refuses a type, not a seat.
	for _, seat := range []string{"0", "123", "true", "null"} {
		t.Run("string "+seat, func(t *testing.T) {
			if out, err := helmTemplateCtfUser(t, seat, "--set-string", "username="+seat, "--set", "dnsSuffix=ctf.example.invalid"); err != nil {
				t.Fatalf("--set-string username=%s was refused: %v\n%s", seat, err, out)
			}
		})
	}
}

func TestSeatGrammar_JustOutsideTheGrammarIsRefusedByHelm(t *testing.T) {
	for name, seat := range map[string]string{
		"54 characters": "a" + strings.Repeat("b", 53),
		"63 characters": "a" + strings.Repeat("b", 62),
		"trailing -":    "user1-",
		"only -":        "-",
	} {
		t.Run(name, func(t *testing.T) {
			if identity.ValidSeat(seat) {
				t.Fatalf("%q is a seat by identity.SeatPattern: the case list and the grammar disagree", seat)
			}
			docs, out, err := renderSeat(t, seat)
			if err == nil {
				// The test must be able to fail: if helm accepted it, the grammar
				// would be narrower than the deploy needs, and say so.
				t.Fatalf("helm template accepted the release name %q (%d objects): the deployable set is wider than the grammar; see ADR-0042", seat, len(docs))
			}
			if !strings.Contains(out, "release name") {
				t.Fatalf("helm failed for %q, but not on the release name: %s", seat, out)
			}
		})
	}
}

// The checker itself has teeth: names a Kubernetes object cannot carry are
// reported, so the passing render above means something.
func TestSeatViolations_Mutations(t *testing.T) {
	long := "a" + strings.Repeat("b", 60) // a 61-character seat: ctf-<seat> is 65
	for name, c := range map[string]struct {
		seat string
		d    seatDerived
	}{
		"namespace over 63":      {long, seatDerived{}},
		"namespace of another":   {"user1", seatDerived{namespaces: []string{"ctf-user2"}}},
		"label ends in -":        {"user1", seatDerived{labelValues: []string{"user1-"}}},
		"host label over 63":     {"user1", seatDerived{hosts: []string{strings.Repeat("a", 64) + ".ctf.example.invalid"}}},
		"host label ends in -":   {"user1", seatDerived{hosts: []string{"user1-.ctf.example.invalid"}}},
		"label over 63 (a seat)": {"user1", seatDerived{labelValues: []string{strings.Repeat("a", 64)}}},
		"label read as a number": {"0", seatDerived{notStrings: []string{"falco-ctf/username=0 (int)"}}},
	} {
		if v := seatViolations(c.seat, c.d); len(v) == 0 {
			t.Errorf("%s: no violation reported", name)
		}
	}
	if v := seatViolations("user1", seatDerived{namespaces: []string{"ctf-user1"}, labelValues: []string{"user1"}, hosts: []string{"user1.ctf.example.invalid"}}); len(v) != 0 {
		t.Errorf("a clean set was flagged: %v", v)
	}
}
