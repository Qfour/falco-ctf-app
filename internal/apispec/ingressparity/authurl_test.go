package ingressparity

// ADR-0034 V12 — see ingressauth.go for the premise. Unlike this package's
// other helm tests (requireHelm SKIPS when helm is missing), these FAIL: a
// skipped V12 would be a silently-green "no Ingress is unauthenticated".

import (
	"os/exec"
	"strings"
	"testing"
)

func v12MustHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm is not on PATH: ADR-0034 V12 renders every chart and may not be skipped (Dockerfile.test installs helm; a local run needs it too)")
	}
}

// v12Rendered renders every recipe once and returns chart -> username -> ingresses.
func v12Rendered(t *testing.T) map[string]map[string][]AuthIngress {
	t.Helper()
	v12MustHelm(t)
	res := map[string]map[string][]AuthIngress{}
	for _, r := range Recipes() {
		got, err := RenderIngresses(r)
		if err != nil {
			t.Fatalf("render %s (%s): %v (did `helm dependency build` run for every chart? Dockerfile.test does it)", r.Chart, r.Username, err)
		}
		if res[r.Chart] == nil {
			res[r.Chart] = map[string][]AuthIngress{}
		}
		res[r.Chart][r.Username] = got
	}
	return res
}

// V12: every chart's Ingress count is pinned, each Ingress carries exactly its
// role's auth-policy endpoint, none lacks an auth-url, and all three identity
// headers are listed. A NEW chart without a recipe fails.
func TestV12_EveryIngressUsesItsRolesAuthEndpoint(t *testing.T) {
	rendered := v12Rendered(t)

	charts, err := AppCharts()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range Recipes() {
		have[r.Chart] = true
	}
	for _, c := range charts {
		if !have[c] {
			t.Errorf("chart %q has no V12 render recipe: add one to Recipes() (and pin its Ingress count) so a new chart cannot add an unauthenticated Ingress unseen", c)
		}
	}
	if len(charts) < 5 {
		t.Fatalf("AppCharts() = %v: extraction is broken (want at least scoreboard, docs, ctf-user, auth-policy, collector)", charts)
	}

	total, withoutAuthURL := 0, 0
	for _, r := range Recipes() {
		got := rendered[r.Chart][r.Username]
		for _, g := range got {
			total++
			if g.Annotations["nginx.ingress.kubernetes.io/auth-url"] == "" {
				withoutAuthURL++
			}
		}
		for _, v := range CheckAuthIngresses(r.Chart, r.Username, got) {
			t.Errorf("%s", v)
		}
	}
	// Non-vacuous: scoreboard 2 + docs 1 + ctf-user 1 x 2 usernames.
	if total != 5 {
		t.Fatalf("rendered %d Ingress objects in total, want 5 (scoreboard 2, docs 1, ctf-user 1 per username x2): the extraction is broken, not clean", total)
	}
	if withoutAuthURL != 0 {
		t.Errorf("%d Ingress objects have no auth-url, want 0", withoutAuthURL)
	}
}

// V12: the pin has teeth. Each mutation of a real rendered Ingress set must
// produce at least one violation, the unmutated set none.
func TestV12_MutationsAreCaught(t *testing.T) {
	rendered := v12Rendered(t)
	clone := func(in []AuthIngress) []AuthIngress {
		out := make([]AuthIngress, len(in))
		for i, g := range in {
			cp := AuthIngress{Name: g.Name, Hosts: append([]string(nil), g.Hosts...), Annotations: map[string]string{}}
			for k, v := range g.Annotations {
				cp.Annotations[k] = v
			}
			out[i] = cp
		}
		return out
	}
	set := func(in []AuthIngress, name, key, val string) {
		for i := range in {
			if in[i].Name == name {
				if val == "\x00delete" {
					delete(in[i].Annotations, key)
				} else {
					in[i].Annotations[key] = val
				}
				return
			}
		}
		panic("no ingress " + name)
	}
	const authKey = "nginx.ingress.kubernetes.io/auth-url"
	const hdrKey = "nginx.ingress.kubernetes.io/auth-response-headers"

	sb := rendered["scoreboard"][""]
	ws := rendered["ctf-user"]["user7"]
	docs := rendered["docs"][""]
	if len(sb) != 2 || len(ws) != 1 || len(docs) != 1 {
		t.Fatalf("unexpected real render: scoreboard=%d ctf-user=%d docs=%d", len(sb), len(ws), len(docs))
	}
	// controls
	for _, c := range []struct {
		chart, user string
		in          []AuthIngress
	}{{"scoreboard", "", sb}, {"ctf-user", "user7", ws}, {"docs", "", docs}} {
		if v := CheckAuthIngresses(c.chart, c.user, c.in); len(v) != 0 {
			t.Fatalf("control (%s) already violates: %v", c.chart, v)
		}
	}

	type mut struct {
		name, chart, user string
		apply             func([]AuthIngress) []AuthIngress
	}
	muts := []mut{
		{"journey -> oauth2-proxy directly (the old any-login door)", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard-journey", authKey, "http://oauth2-proxy.oauth2-proxy.svc.cluster.local:80/oauth2/auth")
			return in
		}},
		{"journey -> /check-workspace", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard-journey", authKey, AuthPolicyBase+"/check-workspace?host=user7")
			return in
		}},
		{"journey -> /check-admin (participants locked out)", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard-journey", authKey, AuthPolicyBase+"/check-admin")
			return in
		}},
		{"admin -> /check-participant (any rostered participant reaches the operator dashboard)", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard", authKey, AuthPolicyBase+"/check-participant")
			return in
		}},
		{"endpoints swapped between journey and admin", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard-journey", authKey, AuthPolicyBase+"/check-admin")
			set(in, "scoreboard", authKey, AuthPolicyBase+"/check-participant")
			return in
		}},
		{"workspace -> /check-participant", "ctf-user", "user7", func(in []AuthIngress) []AuthIngress {
			set(in, "ttyd", authKey, AuthPolicyBase+"/check-participant")
			return in
		}},
		{"workspace -> another user's host=", "ctf-user", "user7", func(in []AuthIngress) []AuthIngress {
			set(in, "ttyd", authKey, AuthPolicyBase+"/check-workspace?host=user8")
			return in
		}},
		{"workspace -> /check-workspace without host=", "ctf-user", "user7", func(in []AuthIngress) []AuthIngress {
			set(in, "ttyd", authKey, AuthPolicyBase+"/check-workspace")
			return in
		}},
		{"workspace host not under the username", "ctf-user", "user7", func(in []AuthIngress) []AuthIngress {
			in[0].Hosts = []string{"user8.ctf.example.invalid"}
			return in
		}},
		{"workspace without any auth-url (the old auth.enabled=false)", "ctf-user", "user7", func(in []AuthIngress) []AuthIngress {
			set(in, "ttyd", authKey, "\x00delete")
			return in
		}},
		{"journey without any auth-url", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard-journey", authKey, "\x00delete")
			return in
		}},
		{"docs-admin -> oauth2-proxy", "docs", "", func(in []AuthIngress) []AuthIngress {
			set(in, "docs-admin", authKey, "http://oauth2-proxy.oauth2-proxy.svc.cluster.local:80/oauth2/auth")
			return in
		}},
		{"docs-admin -> /check-participant", "docs", "", func(in []AuthIngress) []AuthIngress {
			set(in, "docs-admin", authKey, AuthPolicyBase+"/check-participant")
			return in
		}},
		{"auth-url with a look-alike host", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			set(in, "scoreboard-journey", authKey, "http://auth-policy.evil.svc.cluster.local:80/check-participant")
			return in
		}},
		{"an extra, unpinned Ingress appears", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			return append(in, AuthIngress{Name: "scoreboard-extra", Annotations: map[string]string{authKey: AuthPolicyBase + "/check-participant", hdrKey: strings.Join(IdentityHeaders, ",")}})
		}},
		{"an Ingress disappears", "scoreboard", "", func(in []AuthIngress) []AuthIngress { return in[:1] }},
		{"a new chart's Ingress with no pin", "newchart", "", func(in []AuthIngress) []AuthIngress { return in[:1] }},
	}
	for _, id := range IdentityHeaders {
		id := id
		muts = append(muts, mut{"journey drops " + id + " from auth-response-headers", "scoreboard", "", func(in []AuthIngress) []AuthIngress {
			var keep []string
			for _, h := range IdentityHeaders {
				if h != id {
					keep = append(keep, h)
				}
			}
			set(in, "scoreboard-journey", hdrKey, strings.Join(keep, ","))
			return in
		}})
	}
	muts = append(muts,
		mut{"docs-admin has no auth-response-headers", "docs", "", func(in []AuthIngress) []AuthIngress {
			set(in, "docs-admin", hdrKey, "\x00delete")
			return in
		}},
	)
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			var base []AuthIngress
			switch m.chart {
			case "scoreboard", "newchart":
				base = sb
			case "ctf-user":
				base = ws
			case "docs":
				base = docs
			}
			got := m.apply(clone(base))
			if v := CheckAuthIngresses(m.chart, m.user, got); len(v) == 0 {
				t.Fatalf("mutation %q went undetected by CheckAuthIngresses", m.name)
			}
		})
	}
}

// V12: the free-form annotation passthroughs cannot replace the gate, and the
// obsolete values that used to choose the auth endpoint (or turn the gate off)
// fail the render instead of being silently ignored. Each case is the ONLY
// change to an otherwise-valid recipe.
func TestV12_RenderTimeGuards(t *testing.T) {
	v12MustHelm(t)
	base := map[string][]string{}
	for _, r := range Recipes() {
		if _, ok := base[r.Chart]; !ok {
			base[r.Chart] = r.Args
		}
	}
	const prefix = `nginx\.ingress\.kubernetes\.io/`
	type tc struct {
		name, chart, set, wantErr string
	}
	var cases []tc
	// D4: the whole nginx.ingress.kubernetes.io/auth- namespace is refused (prefix
	// match), including the cache and subrequest-shaping keys that do not
	// replace the endpoint but let one caller's 200 be reused for another
	// (auth-cache-key / auth-cache-duration), keep a removed seat admitted for
	// the cache period, or change what the subrequest carries (auth-snippet /
	// auth-proxy-set-headers). auth-signin is also refused here: the chart owns
	// it through the dedicated ingress.authSignin value.
	for _, key := range []string{"auth-url", "auth-response-headers", "auth-cache-key", "auth-cache-duration", "auth-snippet", "auth-proxy-set-headers", "auth-signin", "auth-method", "auth-tls-secret"} {
		cases = append(cases,
			tc{"scoreboard admin passthrough sets " + key, "scoreboard", "ingress.annotations." + prefix + key + "=x", "must not set nginx.ingress.kubernetes.io/" + key},
			tc{"scoreboard journey passthrough sets " + key, "scoreboard", "ingress.journeyAnnotations." + prefix + key + "=x", "must not set nginx.ingress.kubernetes.io/" + key},
			tc{"docs passthrough sets " + key, "docs", "ingress.annotations." + prefix + key + "=x", "must not set nginx.ingress.kubernetes.io/" + key},
		)
	}
	cases = append(cases,
		tc{"stale ingress.journeyAuthUrl", "scoreboard", "ingress.journeyAuthUrl=http://oauth2-proxy.invalid/oauth2/auth", "journeyAuthUrl was removed"},
		tc{"stale ingress.adminAuthUrl", "docs", "ingress.adminAuthUrl=http://x.invalid/check-admin", "adminAuthUrl was removed"},
		tc{"stale auth.enabled=false (an Ingress with no gate)", "ctf-user", "auth.enabled=false", "auth.enabled was removed"},
		tc{"stale auth.enabled=true", "ctf-user", "auth.enabled=true", "auth.enabled was removed"},
		tc{"stale auth.authUrl", "ctf-user", "auth.authUrl=http://oauth2-proxy.invalid/oauth2/auth", "auth.authUrl was removed"},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(append([]string(nil), base[c.chart]...), "--set-string", c.set)
			msg, err := HelmTemplateExpectFailure(c.chart, args...)
			if err == nil {
				t.Fatalf("helm template succeeded with %s; want a render-time failure:\n%s", c.set, msg)
			}
			if !strings.Contains(msg, c.wantErr) {
				t.Fatalf("helm template failed, but not with the guard (%q): an unrelated error would make this test vacuous:\n%s", c.wantErr, msg)
			}
		})
	}
	// The new dedicated value for auth-signin is not the passthrough and still works.
	signinArgs := append(append([]string(nil), base["scoreboard"]...), "--set-string", "ingress.authSignin=https://login.example.invalid/start")
	if msg, err := HelmTemplateExpectFailure("scoreboard", signinArgs...); err != nil {
		t.Fatalf("ingress.authSignin was rejected: %v\n%s", err, msg)
	}
	// The benign passthrough still works (the guard is not "reject all annotations").
	args := append(append([]string(nil), base["scoreboard"]...), "--set-string", `ingress.journeyAnnotations.example\.invalid/team=ctf`)
	if msg, err := HelmTemplateExpectFailure("scoreboard", args...); err != nil {
		t.Fatalf("an unrelated passthrough annotation was rejected: %v\n%s", err, msg)
	}
}

// goodAllowIngress is the scoreboard-allow ingress block as the chart renders it.
const goodAllowIngress = `
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: falco
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
    - from:
        - namespaceSelector:
            matchLabels:
              app.kubernetes.io/name: collector
`

// npDocs builds a scoreboard NetworkPolicy render from the two policies' bodies
// plus any extra documents, so each mutation below is a one-line difference.
func npDocs(allowIngress, denyIngress, extra string) []byte {
	return []byte(`---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scoreboard-default-deny
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
` + denyIngress + `---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scoreboard-allow
spec:
  policyTypes: [Ingress, Egress]
  ingress:` + allowIngress + extra)
}

// V12 / I8 premise: the scoreboard accepts connections only from ingress-nginx
// (after auth-policy), the collector, and falco. The whole chart is rendered
// (no --show-only), so a NetworkPolicy added by any template is seen.
func TestV12_ScoreboardNetworkPolicyAllowsOnlyTheThreeSources(t *testing.T) {
	v12MustHelm(t)
	var args []string
	for _, r := range Recipes() {
		if r.Chart == "scoreboard" {
			args = r.Args
		}
	}
	out, err := helmTemplate("scoreboard", args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "kind: NetworkPolicy") {
		t.Fatal("no NetworkPolicy in the scoreboard render: extraction is broken, not clean")
	}
	for _, v := range CheckScoreboardNetworkPolicies(out) {
		t.Errorf("%s", v)
	}
}

// V12: the NetworkPolicy pin has teeth. The control is clean; each mutation (a
// source that would let a workspace reach the scoreboard directly) is caught.
func TestV12_ScoreboardNetworkPolicyMutationsAreCaught(t *testing.T) {
	if v := CheckScoreboardNetworkPolicies(npDocs(goodAllowIngress, "", "")); len(v) != 0 {
		t.Fatalf("control already violates: %v", v)
	}
	muts := []struct{ name, allow, deny, extra string }{
		{"a rule with ports but no from (all sources)", goodAllowIngress + "    - ports:\n        - port: 8000\n", "", ""},
		{"an empty rule (all sources)", goodAllowIngress + "    - {}\n", "", ""},
		{"from: [] (all sources)", goodAllowIngress + "    - from: []\n", "", ""},
		{"namespaceSelector: {} (every namespace)", goodAllowIngress + "    - from:\n        - namespaceSelector: {}\n", "", ""},
		{"namespaceSelector with matchExpressions only", goodAllowIngress + "    - from:\n        - namespaceSelector:\n            matchExpressions:\n              - {key: kubernetes.io/metadata.name, operator: Exists}\n", "", ""},
		{"matchLabels plus matchExpressions on a pinned source", strings.Replace(goodAllowIngress, "kubernetes.io/metadata.name: falco\n", "kubernetes.io/metadata.name: falco\n            matchExpressions:\n              - {key: x, operator: Exists}\n", 1), "", ""},
		{"a podSelector-only source", goodAllowIngress + "    - from:\n        - podSelector: {}\n", "", ""},
		{"an ipBlock source", goodAllowIngress + "    - from:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n", "", ""},
		{"an extra labelled namespace (ctf-user)", goodAllowIngress + "    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: ctf-user1\n", "", ""},
		{"a pinned source removed", strings.Replace(goodAllowIngress, "kubernetes.io/metadata.name: falco", "kubernetes.io/metadata.name: falco-gone", 1), "", ""},
		{"default-deny admits everything", goodAllowIngress, "  ingress:\n    - {}\n", ""},
		{"a second NetworkPolicy under another name", goodAllowIngress, "", "---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: scoreboard-open\nspec:\n  podSelector: {}\n  ingress:\n    - {}\n"},
	}
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			if v := CheckScoreboardNetworkPolicies(npDocs(m.allow, m.deny, m.extra)); len(v) == 0 {
				t.Fatalf("mutation %q went undetected", m.name)
			}
		})
	}
	t.Run("a required policy is missing", func(t *testing.T) {
		if v := CheckScoreboardNetworkPolicies([]byte("kind: ConfigMap\nmetadata:\n  name: x\n")); len(v) == 0 {
			t.Fatal("a render with no NetworkPolicy must not read as clean")
		}
	})
}

// ADR-0034 V17 (scoreboard half, 条件 14): the roster is personal data and
// belongs to auth-policy alone — the scoreboard Deployment mounts no roster
// volume and has no ROSTER_FILE.
func TestV17_ScoreboardDeploymentHasNoRoster(t *testing.T) {
	v12MustHelm(t)
	out, err := helmTemplate("scoreboard", "--show-only", "templates/deployment.yaml",
		"--set", "env.expectedEmailDomain=ctf.local", "--set", "env.adminEmails=admin@ctf.local")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "kind: Deployment") || !strings.Contains(text, "EXPECTED_EMAIL_DOMAIN") {
		t.Fatalf("scoreboard Deployment did not render as expected: extraction is broken\n%s", text)
	}
	for _, bad := range []string{"roster", "ROSTER_FILE", "auth-policy-roster"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(bad)) {
			t.Errorf("scoreboard Deployment mentions %q: the identity roster must never reach the scoring process", bad)
		}
	}
}
