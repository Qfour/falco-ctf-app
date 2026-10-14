package harness

import (
	"strings"
	"testing"
)

func validEnv() []string {
	return []string{
		"LISTEN_ADDR=127.0.0.1:18000",
		"SCOREBOARD_DB=/tmp/x/scoreboard.db",
		"ALLOWED_ORIGINS=http://127.0.0.1:18001",
		"CHALLENGES_DIR=/src/challenges",
		"SCENARIO_FILE=/src/scenarios/nimbusbreach-full/scenario.yaml",
		"PORTAL_TTYD_SUFFIX=e2e.test",
		"QUEST_ENABLED=true",
		"EXPECTED_EMAIL_DOMAIN=e2e.test",
	}
}

func TestCheckChildEnv_AcceptsTheAllowlistedEnv(t *testing.T) {
	if err := CheckChildEnv(validEnv()); err != nil {
		t.Fatal(err)
	}
}

// Each case is a deliberate break of the child's env; the assertion must name
// it (ADR-0031 V8: "the check is red on a planted violation").
func TestCheckChildEnv_RejectsPlantedViolations(t *testing.T) {
	with := func(extra ...string) []string { return append(validEnv(), extra...) }
	replace := func(key, val string) []string {
		var out []string
		for _, kv := range validEnv() {
			if strings.HasPrefix(kv, key+"=") {
				kv = key + "=" + val
			}
			out = append(out, kv)
		}
		return out
	}
	drop := func(key string) []string {
		var out []string
		for _, kv := range validEnv() {
			if !strings.HasPrefix(kv, key+"=") {
				out = append(out, kv)
			}
		}
		return out
	}
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"FLAGS_FILE would load real flags", with("FLAGS_FILE=/x/flags.yaml"), "FLAGS_FILE"},
		{"ADMIN_EMAILS would make an identity an admin", with("ADMIN_EMAILS=user1@e2e.test"), "ADMIN_EMAILS"},
		{"a webhook secret is not for the harness", with("FALCO_WEBHOOK_SHARED_SECRET=s"), "FALCO_WEBHOOK_SHARED_SECRET"},
		{"an inherited variable outside the allowlist (PATH)", with("PATH=/usr/bin"), "PATH"},
		{"an inherited AWS credential", with("AWS_SECRET_ACCESS_KEY=x"), "AWS_SECRET_ACCESS_KEY"},
		{"listening on all interfaces", replace("LISTEN_ADDR", "0.0.0.0:8000"), "loopback"},
		{"listening on a name instead of a loopback literal", replace("LISTEN_ADDR", "localhost:8000"), "loopback"},
		{"a non-loopback address", replace("LISTEN_ADDR", "10.0.0.5:8000"), "loopback"},
		{"two allowed origins", replace("ALLOWED_ORIGINS", "http://127.0.0.1:1,http://127.0.0.1:2"), "ALLOWED_ORIGINS"},
		{"an origin with a path", replace("ALLOWED_ORIGINS", "http://127.0.0.1:1/x"), "ALLOWED_ORIGINS"},
		{"a real-looking ttyd suffix", replace("PORTAL_TTYD_SUFFIX", "ctf-event.dev"), ".test"},
		{"Quest switched off", replace("QUEST_ENABLED", "false"), "QUEST_ENABLED"},
		{"a missing catalog", drop("CHALLENGES_DIR"), "CHALLENGES_DIR"},
		{"a relative DB path (an empty WorkDir)", replace("SCOREBOARD_DB", "scoreboard.db"), "absolute"},
		{"an identity domain other than the synthetic one", replace("EXPECTED_EMAIL_DOMAIN", "ctf.dev"), "EXPECTED_EMAIL_DOMAIN"},
		{"no identity domain (S2: nobody is self)", drop("EXPECTED_EMAIL_DOMAIN"), "EXPECTED_EMAIL_DOMAIN"},
		{"a variable set twice", with("QUEST_ENABLED=true"), "twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckChildEnv(c.env)
			if err == nil {
				t.Fatalf("CheckChildEnv accepted %v", c.env)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q should mention %q", err, c.want)
			}
		})
	}
}

func TestScoreboardConfigEnv_ComesFromTheAllowlistAlone(t *testing.T) {
	t.Setenv("FLAGS_FILE", "/real/flags.yaml")
	t.Setenv("ADMIN_EMAILS", "root@ops.invalid")
	env, err := ScoreboardConfig{
		Binary: "/x", WorkDir: "/tmp/w", ChallengesDir: "/src/challenges",
		ScenarioFile: "/src/s.yaml", AllowedOrigin: "http://127.0.0.1:1", TtydSuffix: "e2e.test",
	}.Env()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, k := range ChildEnvAllowlist {
		allowed[k] = true
	}
	if len(env) != len(ChildEnvAllowlist) {
		t.Errorf("env has %d entries, the allowlist has %d: %v", len(env), len(ChildEnvAllowlist), env)
	}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !allowed[k] {
			t.Errorf("env carries %s, which is not allowlisted", k)
		}
		if strings.Contains(kv, "/real/flags.yaml") || strings.Contains(kv, "root@ops.invalid") {
			t.Errorf("the parent's environment leaked into the child: %s", kv)
		}
	}
}

func TestScoreboardConfigEnv_RefusesAnEmptyOrRelativeWorkDir(t *testing.T) {
	for _, wd := range []string{"", "work", "./w"} {
		_, err := ScoreboardConfig{
			Binary: "/x", WorkDir: wd, ChallengesDir: "/src/challenges",
			ScenarioFile: "/src/s.yaml", AllowedOrigin: "http://127.0.0.1:1", TtydSuffix: "e2e.test",
		}.Env()
		if err == nil || !strings.Contains(err.Error(), "WorkDir") {
			t.Errorf("WorkDir %q: Env() = %v, want it refused", wd, err)
		}
	}
}
