package authpolicy_test

// ADR-0034 V9: the roster resolution as seen through the three check endpoints.
// Every identity here is a synthetic reserved-domain address (D11).

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

var cookie = map[string]string{"Cookie": "_oauth2_proxy=fake-session"}

// resolveCase is one (identity, endpoint) -> status expectation.
type resolveCase struct {
	name     string
	identity string // X-Auth-Request-Email oauth2-proxy returns ("" = header absent)
	target   string
	want     int
}

// V9: an identity that is not in the roster is 403 on BOTH roster endpoints,
// an external is its own seat and no other, admin passes both, and `/check`
// no longer exists. This is the behavioural pin for "前方一致に戻す mutation で
// 赤": with the old HasPrefix(email, host+"@") rule, case 1 and 2 below would be
// 200.
func TestV9_Resolution(t *testing.T) {
	cases := []resolveCase{
		// not in the roster: the external-domain look-alike of a real seat (C1)
		{"foreign user7@ domain, workspace", "user7@other.example", "/check-workspace?host=user7", 403},
		{"foreign user7@ domain, participant", "user7@other.example", "/check-participant", 403},
		{"foreign domain that merely ends in the seat domain", "user7@evil.ctf.local", "/check-workspace?host=user7", 403},
		{"seat domain with a different local part (not a seat)", "user99@ctf.local", "/check-participant", 403},
		{"+tag on a non-google domain is NOT folded", "user7.ext+x@partner.example", "/check-participant", 403},
		{"prefix of a real seat (user1 vs user10)", "user1@other.example", "/check-workspace?host=user10", 403},
		{"seat is a prefix of the identity (user10 is not user1)", "user10@ctf.local", "/check-workspace?host=user1", 403},
		{"upstream returned no email header", "", "/check-participant", 403},
		{"upstream returned no email header, workspace", "", "/check-workspace?host=user7", 403},
		{"non-ASCII look-alike of a seat (ToLower folds U+212A to k)", "mar\u212a@ctf.local", "/check-participant", 403},
		{"the real seat it imitates", "mark@ctf.local", "/check-participant", 200},
		{"local part empty after gmail folding", "+x@gmail.com", "/check-participant", 403},
		{"local part empty after gmail folding, workspace", "...@googlemail.com", "/check-workspace?host=user7", 403},

		// rostered
		{"static seat on its own workspace", "user7@ctf.local", "/check-workspace?host=user7", 200},
		{"static seat on participant", "user7@ctf.local", "/check-participant", 200},
		{"static seat on another workspace", "user7@ctf.local", "/check-workspace?host=user8", 403},
		{"external is user7 on user7", "user7.ext@partner.example", "/check-workspace?host=user7", 200},
		{"external is user7 on participant", "user7.ext@partner.example", "/check-participant", 200},
		{"external is user7 only: not user8", "user7.ext@partner.example", "/check-workspace?host=user8", 403},
		{"external matches case-insensitively", "USER7.EXT@Partner.Example", "/check-workspace?host=user7", 200},
		{"row spelled with capitals is normalised (bob)", "bob.ext@partner.example", "/check-workspace?host=bob", 200},
		{"seat matches case-insensitively", "User7@CTF.local", "/check-workspace?host=user7", 200},

		// admin
		{"admin on any workspace", "admin@ctf.local", "/check-workspace?host=user7", 200},
		{"admin on participant", "Admin@CTF.local", "/check-participant", 200},
		{"admin on admin", "admin@ctf.local", "/check-admin", 200},
		{"rostered seat is not admin", "user7@ctf.local", "/check-admin", 403},
		{"rostered external is not admin", "user7.ext@partner.example", "/check-admin", 403},

		// the old route is gone (a stale chart -> 404 -> ingress 500: closed)
		{"/check is removed (rostered identity)", "user7@ctf.local", "/check?host=user7", 404},
		{"/check is removed (admin)", "admin@ctf.local", "/check?host=user7", 404},
		{"/check is removed (bare)", "admin@ctf.local", "/check", 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := fakeOAuth2Proxy(t, func(*http.Request) (int, string) { return http.StatusAccepted, c.identity })
			defer up.Close()
			h := newAdminHandler(up.URL, fixtureAdmin)
			resp := do(t, h, c.target, cookie)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != c.want {
				t.Fatalf("%s as %q: got %d (%s), want %d", c.target, c.identity, resp.StatusCode, body, c.want)
			}
		})
	}
}

// V9: for a rostered identity the three identity headers are the canonical
// form and NOTHING the IdP returned, even when oauth2-proxy returns a User /
// Preferred-Username that is not the seat (a Google `sub`, an attacker-chosen
// display value, "admin"). Both roster endpoints, both kinds of identity.
func TestV9_CanonicalHeadersOverwriteUpstream(t *testing.T) {
	type tc struct {
		name, email, wantSeat string
	}
	cases := []tc{
		{"static seat", "user7@ctf.local", "user7"},
		{"external seat", "user7.ext@partner.example", "user7"},
		{"external spelled differently", "USER7.EXT@PARTNER.EXAMPLE", "user7"},
	}
	for _, c := range cases {
		for _, target := range []string{"/check-workspace?host=user7", "/check-participant"} {
			t.Run(c.name+" "+target, func(t *testing.T) {
				up := fakeUpstream(t, map[string]string{
					"X-Auth-Request-Email":              c.email,
					"X-Auth-Request-User":               "117283746501928374650", // a Google-style sub
					"X-Auth-Request-Preferred-Username": "admin",
					"X-Auth-Request-Groups":             "ops,admins",
				})
				defer up.Close()
				h := newAdminHandler(up.URL, fixtureAdmin)
				resp := do(t, h, target, cookie)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("got %d, want 200", resp.StatusCode)
				}
				for hdr, want := range map[string]string{
					"X-Auth-Request-Email":              c.wantSeat + "@ctf.local",
					"X-Auth-Request-User":               c.wantSeat,
					"X-Auth-Request-Preferred-Username": c.wantSeat,
				} {
					if got := resp.Header.Values(hdr); len(got) != 1 || got[0] != want {
						t.Errorf("%s = %q, want exactly [%q]", hdr, got, want)
					}
				}
				// nothing else from the IdP is forwarded, and the IdP's
				// email appears in no header value.
				if got := resp.Header.Get("X-Auth-Request-Groups"); got != "" {
					t.Errorf("X-Auth-Request-Groups leaked: %q", got)
				}
				for k, vs := range resp.Header {
					for _, v := range vs {
						if strings.Contains(strings.ToLower(v), "partner.example") || strings.Contains(v, "117283746501928374650") {
							t.Errorf("response header %s=%q carries the IdP's identity", k, v)
						}
					}
				}
			})
		}
	}
}

// V9: an ADMIN_EMAILS member is passed through unchanged ("現行どおり透過").
func TestV9_AdminHeadersPassThrough(t *testing.T) {
	up := fakeUpstream(t, map[string]string{
		"X-Auth-Request-Email":              "admin@ctf.local",
		"X-Auth-Request-User":               "admin",
		"X-Auth-Request-Preferred-Username": "admin",
	})
	defer up.Close()
	h := newAdminHandler(up.URL, fixtureAdmin)
	for _, target := range []string{"/check-workspace?host=user7", "/check-participant", "/check-admin"} {
		resp := do(t, h, target, cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: got %d", target, resp.StatusCode)
		}
		if got := resp.Header.Get("X-Auth-Request-Email"); got != "admin@ctf.local" {
			t.Errorf("%s: admin email header = %q", target, got)
		}
	}
}

// V9: no 403 body (any endpoint) carries the caller's email, seat or host. The
// old bodies echoed `%q` of the email (server.go:253,283). Every denial path is
// covered: not in the roster, a rostered seat on the wrong host, a rostered
// seat on the admin gate.
func TestV9_ForbiddenBodiesCarryNoIdentity(t *testing.T) {
	cases := []struct{ identity, target string }{
		{"someone.private@stranger.example", "/check-workspace?host=user7"},
		{"someone.private@stranger.example", "/check-participant"},
		{"someone.private@stranger.example", "/check-admin"},
		{"user7@ctf.local", "/check-workspace?host=user8"},
		{"user7@ctf.local", "/check-admin"},
		{"user7.ext@partner.example", "/check-workspace?host=user8"},
		{"user7.ext@partner.example", "/check-admin"},
	}
	for _, c := range cases {
		t.Run(c.identity+" "+c.target, func(t *testing.T) {
			up := fakeOAuth2Proxy(t, func(*http.Request) (int, string) { return http.StatusAccepted, c.identity })
			defer up.Close()
			h := newAdminHandler(up.URL, fixtureAdmin)
			resp := do(t, h, c.target, cookie)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d (%s), want 403", resp.StatusCode, body)
			}
			if strings.TrimSpace(string(body)) != "forbidden" {
				t.Errorf("403 body = %q, want the fixed string \"forbidden\"", body)
			}
		})
	}
}

// V9: /healthz reports the roster size (counts only) and /check-workspace's
// other denial path (a rostered identity on the wrong host) keeps the body
// free of the host and the seat too.
func TestV9_HealthzReportsRosterCounts(t *testing.T) {
	h := newAdminHandler("http://oauth2-proxy.invalid", fixtureAdmin)
	resp := do(t, h, "/healthz", nil)
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["roster_seats"] != float64(7) || got["roster_external"] != float64(2) {
		t.Fatalf("healthz = %v, want roster_seats=7 roster_external=2", got)
	}
	for k, v := range got {
		if s, ok := v.(string); ok && strings.Contains(s, "@") {
			t.Errorf("healthz field %s=%q looks like an address", k, s)
		}
	}
}

// A Handler built without a roster (a programming error in a caller; main
// refuses to start) resolves nobody: roster endpoints answer 403 to every
// non-admin. Fail-closed, never "everyone".
func TestV9_NilRosterIsFailClosed(t *testing.T) {
	up := fakeOAuth2Proxy(t, func(*http.Request) (int, string) { return http.StatusAccepted, "user7@ctf.local" })
	defer up.Close()
	h := newNoRosterHandler(up.URL)
	for _, target := range []string{"/check-workspace?host=user7", "/check-participant"} {
		if resp := do(t, h, target, cookie); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with no roster: got %d, want 403", target, resp.StatusCode)
		}
	}
	if resp := do(t, h, "/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("healthz with no roster: %d", resp.StatusCode)
	}
}
