package ingressparity

// app#534 (ADR-0044 residual (a)): the workspace Ingress's auth-signin annotation, the
// first hop of the sign-in redirect, is https. Its default used to be http://<appHost>/...
// while the frame-ancestors on the same host were already https only.
//
// Like frame_ancestors_render_test.go it FAILS when helm is missing.

import (
	"errors"
	"io"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ttydAuthSignin renders charts/ctf-user and returns the auth-signin annotation of the
// ttyd Ingress, as decoded from the YAML.
func ttydAuthSignin(t *testing.T, args ...string) string {
	t.Helper()
	base := []string{"--set-string", "username=user1", "--set", "dnsSuffix=ctf.example.invalid"}
	out, err := helmTemplateCtfUser(t, "user1", append(base, args...)...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	dec := yaml.NewDecoder(strings.NewReader(out))
	var found []string
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name        string            `yaml:"name"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
		}
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("the rendered manifest does not parse as YAML: %v\n%s", err, out)
		}
		if doc.Kind != "Ingress" || doc.Metadata.Name != "ttyd" {
			continue
		}
		if v, ok := doc.Metadata.Annotations["nginx.ingress.kubernetes.io/auth-signin"]; ok {
			found = append(found, v)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one auth-signin annotation on the ttyd Ingress, found %d: %q", len(found), found)
	}
	return found[0]
}

// The nginx variables stay literal (nginx expands them per request, helm must not).
const authSigninRd = "?rd=$scheme://$host$escaped_request_uri"

func TestAuthSignin_DefaultIsHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"app host given (deploy-user.sh --app-host)", []string{"--set-string", "auth.appHost=app.example.invalid"},
			"https://app.example.invalid/oauth2/start" + authSigninRd},
		{"no app host: the auth.<dnsSuffix> compat bridge", nil,
			"https://auth.ctf.example.invalid/oauth2/start" + authSigninRd},
	} {
		got := ttydAuthSignin(t, tc.args...)
		if got != tc.want {
			t.Errorf("%s: auth-signin = %q, want %q", tc.name, got, tc.want)
		}
		if strings.HasPrefix(got, "http://") {
			t.Errorf("%s: auth-signin %q starts with http://", tc.name, got)
		}
	}
}

// The override the CHANGELOG promises for an environment that only serves http still works.
func TestAuthSignin_CanBeOverridden(t *testing.T) {
	const v = "http://app.example.invalid/oauth2/start" + authSigninRd
	if got := ttydAuthSignin(t, "--set-string", "auth.authSignin="+v); got != v {
		t.Errorf("auth-signin = %q, want the override %q", got, v)
	}
}
