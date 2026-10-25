package ingressparity

// ADR-0034 V12 / Hard Invariant I8's header-completeness premise: EVERY Ingress
// any app chart renders sends its auth subrequest to the right auth-policy
// endpoint for its role, and lists the identity headers auth-policy rewrites.
//
// The premise (ADR-0034 D7): a request reaches a backend only through an Ingress
// whose auth-url is auth-policy, which overwrites X-Auth-Request-{Email,User,
// Preferred-Username}. An Ingress that pointed at oauth2-proxy directly (the old
// journey Ingress), that had no auth-url at all (the old `auth.enabled: false`
// workspace Ingress), or that carried the WRONG auth-policy endpoint for its
// role (a participant door on the workspace, a workspace check on the portal)
// silently reintroduces "any authenticated login" or "no gate". The role ->
// endpoint table below is the pin; it is derived from `helm template` output,
// never from the template source, so a values/annotation path cannot hide a
// difference.
//
// Like the rest of this package it is imported ONLY from *_test.go files (it
// shells out to helm and reads YAML).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthPolicyBase is the in-cluster auth-policy Service every app Ingress's
// auth-url points at.
const AuthPolicyBase = "http://auth-policy.auth-policy.svc.cluster.local:80"

// IdentityHeaders are the three headers auth-policy rewrites to the canonical
// form; every Ingress must list all of them in auth-response-headers or the
// client-supplied copy of the missing one reaches the backend.
var IdentityHeaders = []string{"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Preferred-Username"}

// Recipe is one `helm template` invocation: a chart plus the values that make
// every Ingress it can render appear.
type Recipe struct {
	Chart    string
	Username string // ctf-user only: the workspace username under test
	Args     []string
}

// Recipes returns the render recipes. ctf-user is rendered with two usernames
// so the `host=` query cannot be a constant that merely happens to match one.
// The username is passed with --set-string, as deploy-user.sh does: the chart refuses
// a username that is not a string (ADR-0042 C4).
func Recipes() []Recipe {
	return []Recipe{
		{Chart: "scoreboard", Args: []string{
			"--set", "ingress.enabled=true",
			"--set", "ingress.host=app.example.invalid",
			"--set", "ingress.journeyHost=app.example.invalid",
		}},
		{Chart: "docs", Args: []string{"--set", "ingress.adminHost=app.example.invalid"}},
		{Chart: "ctf-user", Username: "user7", Args: []string{"--set-string", "username=user7", "--set", "dnsSuffix=ctf.example.invalid"}},
		{Chart: "ctf-user", Username: "user42", Args: []string{"--set-string", "username=user42", "--set", "dnsSuffix=ctf.example.invalid"}},
		{Chart: "auth-policy"},
		{Chart: "collector"},
	}
}

// ExpectedCount is the number of Ingress objects each chart renders under its
// recipe. A chart that gains or loses an Ingress must change this table (and
// the role pin below) in the same PR.
var ExpectedCount = map[string]int{
	"scoreboard":  2, // scoreboard (admin, /check-admin) + scoreboard-journey (participant, /check-participant)
	"docs":        1, // docs-admin (/check-admin)
	"ctf-user":    1, // ttyd (/check-workspace?host=<username>)
	"auth-policy": 0,
	"collector":   0,
}

// RolePin maps "<chart>/<ingress name>" to the exact auth-url that role must
// carry. username is the recipe's Username (only ctf-user uses it).
func RolePin(chart, name, username string) (string, bool) {
	switch chart + "/" + name {
	case "scoreboard/scoreboard-journey":
		return AuthPolicyBase + "/check-participant", true
	case "scoreboard/scoreboard", "docs/docs-admin":
		return AuthPolicyBase + "/check-admin", true
	case "ctf-user/ttyd":
		return AuthPolicyBase + "/check-workspace?host=" + username, true
	}
	return "", false
}

// AuthIngress is the part of a rendered Ingress V12 reads.
type AuthIngress struct {
	Name        string
	Hosts       []string
	Annotations map[string]string
}

type renderedAuthIngress struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		Rules []struct {
			Host string `yaml:"host"`
		} `yaml:"rules"`
	} `yaml:"spec"`
}

// RenderIngresses runs `helm template charts/<chart>` for the recipe (NO
// --show-only: any template that renders an Ingress is found) and returns every
// Ingress in the output.
func RenderIngresses(r Recipe) ([]AuthIngress, error) {
	out, err := helmTemplate(r.Chart, r.Args...)
	if err != nil {
		return nil, err
	}
	return parseAuthIngresses(out)
}

func helmTemplate(chart string, args ...string) ([]byte, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("helm", append([]string{"template", filepath.Join("charts", chart)}, args...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("helm template charts/%s %v: %w\n%s", chart, args, err, out)
	}
	return out, nil
}

// HelmTemplateExpectFailure renders and returns helm's combined output; the
// caller asserts the error. Exported for the render-time `fail` guards' tests.
func HelmTemplateExpectFailure(chart string, args ...string) (string, error) {
	out, err := helmTemplate(chart, args...)
	if err != nil {
		return err.Error(), err
	}
	return string(out), nil
}

func parseAuthIngresses(doc []byte) ([]AuthIngress, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	var res []AuthIngress
	for {
		var ri renderedAuthIngress
		if err := dec.Decode(&ri); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parse helm output: %w", err)
		}
		if ri.Kind != "Ingress" {
			continue
		}
		ai := AuthIngress{Name: ri.Metadata.Name, Annotations: ri.Metadata.Annotations}
		for _, rule := range ri.Spec.Rules {
			ai.Hosts = append(ai.Hosts, rule.Host)
		}
		res = append(res, ai)
	}
	return res, nil
}

// CheckAuthIngresses is the pure comparison (testable with synthetic input):
// it returns one human-readable violation per problem for the Ingresses chart
// rendered under the recipe's username.
func CheckAuthIngresses(chart, username string, got []AuthIngress) []string {
	var v []string
	want, known := ExpectedCount[chart]
	if !known {
		v = append(v, fmt.Sprintf("chart %q has no ExpectedCount entry: add it (and a RolePin for each Ingress it renders)", chart))
	} else if len(got) != want {
		names := make([]string, 0, len(got))
		for _, g := range got {
			names = append(names, g.Name)
		}
		sort.Strings(names)
		v = append(v, fmt.Sprintf("chart %s renders %d Ingress objects %v, want %d", chart, len(got), names, want))
	}
	for _, ing := range got {
		id := chart + "/" + ing.Name
		pin, ok := RolePin(chart, ing.Name, username)
		if !ok {
			v = append(v, fmt.Sprintf("%s: Ingress has no role pin (RolePin); every Ingress needs one so its auth endpoint is checked", id))
			continue
		}
		authURL, has := ing.Annotations["nginx.ingress.kubernetes.io/auth-url"]
		if !has || authURL == "" {
			v = append(v, fmt.Sprintf("%s: no auth-url annotation (an Ingress without an auth gate)", id))
			continue
		}
		if authURL != pin {
			v = append(v, fmt.Sprintf("%s: auth-url = %q, want exactly %q", id, authURL, pin))
		}
		if chart == "ctf-user" {
			for _, h := range ing.Hosts {
				if !strings.HasPrefix(h, username+".") {
					v = append(v, fmt.Sprintf("%s: host %q is not under %q (the host= in auth-url must be the workspace this Ingress serves)", id, h, username+"."))
				}
			}
			if len(ing.Hosts) == 0 {
				v = append(v, fmt.Sprintf("%s: renders no host", id))
			}
		}
		headers := map[string]bool{}
		for _, h := range strings.Split(ing.Annotations["nginx.ingress.kubernetes.io/auth-response-headers"], ",") {
			headers[strings.ToLower(strings.TrimSpace(h))] = true
		}
		for _, need := range IdentityHeaders {
			if !headers[strings.ToLower(need)] {
				v = append(v, fmt.Sprintf("%s: auth-response-headers %q lacks %s (the client's copy would reach the backend)", id, ing.Annotations["nginx.ingress.kubernetes.io/auth-response-headers"], need))
			}
		}
	}
	return v
}

// AppCharts lists the installable (non-library) chart directories under
// charts/, so a NEW chart cannot dodge the count pin by not being in a list.
func AppCharts() ([]string, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, "charts"))
	if err != nil {
		return nil, err
	}
	var charts []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, "charts", e.Name(), "Chart.yaml"))
		if err != nil {
			continue // not a chart directory
		}
		var c struct {
			Type string `yaml:"type"`
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("charts/%s/Chart.yaml: %w", e.Name(), err)
		}
		if c.Type == "library" {
			continue
		}
		charts = append(charts, e.Name())
	}
	sort.Strings(charts)
	return charts, nil
}
