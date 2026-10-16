package ingressparity

import (
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// renderedAnnotations renders ONE scoreboard chart template with `helm
// template --show-only` and returns its metadata.annotations.
func renderedAnnotations(t *testing.T, template string) map[string]string {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("helm", "template", "charts/scoreboard",
		"--show-only", template,
		"--set", "ingress.enabled=true",
		"--set", "ingress.host=app.example.invalid",
		"--set", "ingress.journeyHost=app.example.invalid",
	)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("helm template %s: %v (stderr: %s)", template, err, ee.Stderr)
		}
		t.Fatalf("helm template %s: %v", template, err)
	}
	var doc struct {
		Metadata struct {
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parse %s: %v", template, err)
	}
	if len(doc.Metadata.Annotations) == 0 {
		t.Fatalf("%s rendered no annotations — extraction is broken, not \"nothing to check\"", template)
	}
	return doc.Metadata.Annotations
}

// TestIngresses_StampProxyIdentityHeaders pins the premise the "browser path
// is closed by a 403 on any X-Auth-Request-* header" controls rest on
// (POST /falco/events, POST /internal/exfil/{cid}; the participant display-name
// route that was the first of these is gone, ADR-0034 S1): BOTH
// Ingress objects (the participant journey one and the admin catch-all) must
// run an auth subrequest and list X-Auth-Request-Email in
// auth-response-headers, so every request reaching the scoreboard through a
// browser carries the header. If either annotation were dropped, browser
// requests would arrive header-less and be indistinguishable from the
// collector / falcosidekick path — the 403 would silently stop firing.
func TestIngresses_StampProxyIdentityHeaders(t *testing.T) {
	requireHelm(t)
	for _, template := range []string{"templates/ingress-journey.yaml", "templates/ingress.yaml"} {
		t.Run(template, func(t *testing.T) {
			ann := renderedAnnotations(t, template)
			if ann["nginx.ingress.kubernetes.io/auth-url"] == "" {
				t.Errorf("%s: auth-url annotation missing or empty — browser requests would reach the scoreboard without an auth subrequest, i.e. without X-Auth-Request-* headers", template)
			}
			resp := ann["nginx.ingress.kubernetes.io/auth-response-headers"]
			found := false
			for _, h := range strings.Split(resp, ",") {
				if strings.EqualFold(strings.TrimSpace(h), "X-Auth-Request-Email") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: auth-response-headers = %q, want it to include X-Auth-Request-Email (the header the collector-only / internal routes refuse)", template, resp)
			}
		})
	}
}

// TestIngresses_AuthAnnotationsNotOverridable pins the other half of
// TestIngresses_StampProxyIdentityHeaders: the free-form annotations
// passthrough (ingress.annotations / ingress.journeyAnnotations) must not be
// able to replace auth-url or auth-response-headers. The chart `fail`s at
// render time instead of letting a values typo or a copied annotation block
// silently drop the identity-stamping gate.
func TestIngresses_AuthAnnotationsNotOverridable(t *testing.T) {
	requireHelm(t)
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ template, valuesKey string }{
		{"templates/ingress.yaml", "ingress.annotations"},
		{"templates/ingress-journey.yaml", "ingress.journeyAnnotations"},
	}
	for _, c := range cases {
		for _, key := range []string{"auth-url", "auth-response-headers"} {
			t.Run(c.template+"/"+key, func(t *testing.T) {
				cmd := exec.Command("helm", "template", "charts/scoreboard",
					"--show-only", c.template,
					"--set", "ingress.enabled=true",
					"--set", "ingress.host=app.example.invalid",
					"--set", "ingress.journeyHost=app.example.invalid",
					"--set-string", c.valuesKey+".nginx\\.ingress\\.kubernetes\\.io/"+key+"=x",
				)
				cmd.Dir = root
				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatalf("helm template succeeded with %s overriding %s; want a render-time failure. output:\n%s", c.valuesKey, key, out)
				}
				if !strings.Contains(string(out), "must not set nginx.ingress.kubernetes.io/"+key) {
					t.Fatalf("helm template failed but not with the override guard (unrelated error would make this test vacuous):\n%s", out)
				}
			})
		}
	}
}
