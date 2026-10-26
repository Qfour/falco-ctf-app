package ingressparity

// ADR-0044 D5 / V3 (app#520): charts/ctf-user renders the ttyd-proxy's FRAME_ANCESTORS env
// with `quote`, so a value outside the grammar cannot break the manifest or turn into
// another field of it. The grammar is checked before this (deploy-user.sh) and by
// ttyd-proxy itself at start (ttydproxy.New); this is the layer under both, for a chart
// used without them. Before the change the template was value: "{{ ... }}" and a `"` in
// the value ended the string.
//
// Like seat_render_test.go it FAILS when helm is missing (a skipped render test would be a
// silently-green "the template is safe").

import (
	"errors"
	"io"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// proxyFrameAncestors renders charts/ctf-user with ttyd.frameAncestors=<value> (--set-string,
// as deploy-user.sh passes it) and returns the FRAME_ANCESTORS env of the ttyd-proxy
// container of the workspace Pod, as decoded from the YAML.
func proxyFrameAncestors(t *testing.T, value string) string {
	t.Helper()
	out, err := helmTemplateCtfUser(t, "user1", "--set-string", "username=user1", "--set", "dnsSuffix=ctf.example.invalid",
		"--set-string", "ttyd.frameAncestors="+value)
	if err != nil {
		t.Fatalf("frameAncestors %q: helm template failed: %v\n%s", value, err, out)
	}
	dec := yaml.NewDecoder(strings.NewReader(out))
	var found []string
	for {
		var doc struct {
			Kind string `yaml:"kind"`
			Spec struct {
				Containers []struct {
					Name string `yaml:"name"`
					Env  []struct {
						Name  string  `yaml:"name"`
						Value *string `yaml:"value"`
					} `yaml:"env"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		}
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("frameAncestors %q: the rendered manifest does not parse as YAML (the template did not quote the value): %v\n%s", value, err, out)
		}
		if doc.Kind != "Pod" {
			continue
		}
		for _, c := range doc.Spec.Containers {
			if c.Name != "ttyd-proxy" {
				continue
			}
			for _, e := range c.Env {
				if e.Name == "FRAME_ANCESTORS" && e.Value != nil {
					found = append(found, *e.Value)
				}
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("frameAncestors %q: want exactly one FRAME_ANCESTORS env on the ttyd-proxy container, found %d: %q", value, len(found), found)
	}
	return found[0]
}

func TestFrameAncestorsEnv_IsRenderedQuoted(t *testing.T) {
	for _, v := range []string{
		"'none'",
		"https://app.x.example",
		// Not in the grammar: what a quote-less template turns into a broken or a different manifest.
		// (No backslash row: helm's own --set parser eats it before the template sees it.)
		`a"b`,
		`https://a.example" # x`,
		`"`,
		"a\nb",
		"a\n        - name: INJECTED\n          value: x",
		"null",
		"true",
		"1e3",
	} {
		if got := proxyFrameAncestors(t, v); got != v {
			t.Errorf("FRAME_ANCESTORS = %q, want the value as given, %q", got, v)
		}
	}
}
