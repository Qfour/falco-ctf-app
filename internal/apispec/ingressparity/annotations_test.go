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
// (display-name, POST /falco/events, POST /internal/exfil/{cid}): BOTH
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
