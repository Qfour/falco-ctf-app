package scoreboard_test

// ADR-0038 V5 (app#404): the rendered PrometheusRule and the code agree. The
// chart's alert names a metric and a set of reason values; this renders it with
// monitoring on and checks both against what the scoreboard process registers
// and declares, so renaming either side alone fails `make test` (the rule is
// rendered nowhere today: platform has monitoring off everywhere, so nothing
// else would notice).

import (
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
)

type ruleDoc struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Groups []struct {
			Rules []struct {
				Alert string `yaml:"alert"`
				Expr  string `yaml:"expr"`
				For   string `yaml:"for"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	} `yaml:"spec"`
}

type alertRule struct{ alert, expr, forDuration string }

// renderedRules renders the scoreboard chart with monitoring on and returns its
// PrometheusRule's rules. A missing helm FAILS (like ADR-0034 V12): a skipped
// render would be a silently green "the alert matches the code".
func renderedRules(t *testing.T) []alertRule {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm is not on PATH: ADR-0038 V5 renders the chart and may not be skipped (Dockerfile.test installs helm; a local run needs it too)")
	}
	cmd := exec.Command("helm", "template", "charts/scoreboard", "--set", "monitoring.enabled=true", "--show-only", "templates/prometheusrule.yaml")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("helm template: %v (stderr: %s)", err, ee.Stderr)
		}
		t.Fatalf("helm template: %v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	var rules []alertRule
	for {
		var d ruleDoc
		if err := dec.Decode(&d); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("parse rendered rule: %v", err)
		}
		if d.Kind != "PrometheusRule" {
			continue
		}
		for _, g := range d.Spec.Groups {
			for _, r := range g.Rules {
				rules = append(rules, alertRule{r.Alert, r.Expr, r.For})
			}
		}
	}
	if len(rules) == 0 {
		t.Fatal("rendered 0 rules with monitoring.enabled=true: the extraction is broken, not clean")
	}
	return rules
}

// registeredMetricNames is every fully qualified metric name the process
// registers (from Describe, so a vec with no child yet counts).
func registeredMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	c, ok := prometheus.DefaultRegisterer.(prometheus.Collector)
	if !ok {
		t.Fatal("the default registerer cannot be described")
	}
	ch := make(chan *prometheus.Desc, 256)
	go func() { c.Describe(ch); close(ch) }()
	re := regexp.MustCompile(`fqName: "([^"]+)"`)
	names := map[string]bool{}
	for d := range ch {
		if m := re.FindStringSubmatch(d.String()); m != nil {
			names[m[1]] = true
		}
	}
	return names
}

var ruleMetric = regexp.MustCompile(`\b((?:scoreboard|ratelimit)_[a-z0-9_]+)`)

func metricFamily(name string) []string {
	out := []string{name}
	for _, suf := range []string{"_count", "_sum", "_bucket"} {
		if strings.HasSuffix(name, suf) {
			out = append(out, strings.TrimSuffix(name, suf))
		}
	}
	return out
}

// ruleViolations compares the rendered rules with the process: every scoreboard_*
// and ratelimit_* name in any expr is registered; the identity rule exists, under
// the new name only, alerts on > 0 with no `for`, selects reasons inside the
// declared vocabulary that include no_identity and non_canonical and not mismatch.
func ruleViolations(rules []alertRule, registered map[string]bool, declaredReasons map[string]bool) []string {
	var out []string
	var identity *alertRule
	for i, r := range rules {
		if r.alert == "ScoreboardNoIdentityDenials" {
			out = append(out, "the old alert ScoreboardNoIdentityDenials is still rendered (it reads the retired no_identity outcome)")
		}
		if r.alert == "ScoreboardIdentityDenials" {
			identity = &rules[i]
		}
		for _, m := range ruleMetric.FindAllString(r.expr, -1) {
			found := false
			for _, fam := range metricFamily(m) {
				found = found || registered[fam]
			}
			if !found {
				out = append(out, r.alert+": expr names "+m+", which the scoreboard process does not register")
			}
		}
	}
	if identity == nil {
		return append(out, "no ScoreboardIdentityDenials rule is rendered")
	}
	if !strings.Contains(identity.expr, "scoreboard_identity_denials_total") {
		out = append(out, "ScoreboardIdentityDenials does not read scoreboard_identity_denials_total")
	}
	if !regexp.MustCompile(`>\s*0\s*$`).MatchString(strings.TrimSpace(identity.expr)) {
		out = append(out, "ScoreboardIdentityDenials is not a plain `> 0` (ADR-0038 D5: the floor of a healthy production is 0, so a larger threshold only delays detection)")
	}
	if identity.forDuration != "" {
		out = append(out, "ScoreboardIdentityDenials has a `for:` ("+identity.forDuration+"): the portal gate emits one count per page load")
	}
	m := regexp.MustCompile(`reason=~"([^"]*)"`).FindStringSubmatch(identity.expr)
	if m == nil {
		return append(out, "ScoreboardIdentityDenials selects no reason=~ set")
	}
	sel := map[string]bool{}
	for _, r := range strings.Split(m[1], "|") {
		sel[r] = true
		if !declaredReasons[r] {
			out = append(out, "ScoreboardIdentityDenials selects reason "+r+", which is not in the declared vocabulary")
		}
	}
	for _, r := range []string{"no_identity", "non_canonical"} {
		if !sel[r] {
			out = append(out, "ScoreboardIdentityDenials does not select reason "+r)
		}
	}
	if sel["mismatch"] {
		out = append(out, "ScoreboardIdentityDenials selects reason mismatch: a participant's own action is not an alert (ADR-0038 D5)")
	}
	return out
}

func TestIdentityDenials_AlertMatchesTheCode(t *testing.T) {
	rules := renderedRules(t)
	declared := map[string]bool{}
	for _, p := range identityobs.Declared() {
		declared[string(p.Reason)] = true
	}
	registered := registeredMetricNames(t)
	if !registered["scoreboard_identity_denials_total"] || !registered["ratelimit_identity_requests_total"] {
		t.Fatalf("registeredMetricNames lost the identity metrics (%d names): the extraction is broken, not clean", len(registered))
	}
	if v := ruleViolations(rules, registered, declared); len(v) > 0 {
		t.Fatalf("the rendered PrometheusRule disagrees with the code:\n  %s", strings.Join(v, "\n  "))
	}

	// Not vacuous: each drift is flagged.
	mutate := func(f func(r alertRule) alertRule) []alertRule {
		out := make([]alertRule, len(rules))
		for i, r := range rules {
			if r.alert == "ScoreboardIdentityDenials" {
				r = f(r)
			}
			out[i] = r
		}
		return out
	}
	for name, mutated := range map[string][]alertRule{
		"metric name off by one char": mutate(func(r alertRule) alertRule {
			r.expr = strings.Replace(r.expr, "scoreboard_identity_denials_total", "scoreboard_identity_denial_total", 1)
			return r
		}),
		"mismatch selected": mutate(func(r alertRule) alertRule {
			r.expr = strings.Replace(r.expr, "no_identity|non_canonical", "no_identity|non_canonical|mismatch", 1)
			return r
		}),
		"non_canonical dropped": mutate(func(r alertRule) alertRule {
			r.expr = strings.Replace(r.expr, "no_identity|non_canonical", "no_identity", 1)
			return r
		}),
		"reason outside the vocabulary": mutate(func(r alertRule) alertRule {
			r.expr = strings.Replace(r.expr, "no_identity|non_canonical", "no_identity|empty_identity", 1)
			return r
		}),
		"threshold raised": mutate(func(r alertRule) alertRule {
			r.expr = strings.Replace(strings.TrimSpace(r.expr), "> 0", "> 10", 1)
			return r
		}),
		"for added":      mutate(func(r alertRule) alertRule { r.forDuration = "5m"; return r }),
		"old alert back": append(append([]alertRule(nil), rules...), alertRule{alert: "ScoreboardNoIdentityDenials", expr: `sum(increase(ratelimit_identity_requests_total{outcome="no_identity"}[5m])) > 10`}),
	} {
		if v := ruleViolations(mutated, registered, declared); len(v) == 0 {
			t.Errorf("drift %q was not flagged", name)
		}
	}
}
