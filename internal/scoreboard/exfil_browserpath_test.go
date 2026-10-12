package scoreboard_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The internal-only contract of POST /internal/exfil/{cid} (the admin ingress
// catch-all also routes this path to an admin BROWSER, where oauth2-proxy
// stamps X-Auth-Request-*; the collector never does): any X-Auth-Request-*
// header => 403 before everything else, a non-JSON Content-Type => 415, and
// neither may record a receipt.

const exfilBody = `{"user":"alice","flag":"FALCO{boss}"}`

// exfilReq POSTs /internal/exfil/{cid} with an explicit Content-Type (omitted
// when "") and extra headers. Header keys that are not already canonical are
// assigned to r.Header verbatim (Header.Set would normalise them).
func (f *fixture) exfilReq(cid, contentType, body string, hdr map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest("POST", "/internal/exfil/"+cid, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for k, v := range hdr {
		if k != http.CanonicalHeaderKey(k) {
			r.Header[k] = []string{v}
			continue
		}
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func TestExfilInternal_ProxyIdentityHeader_ForbiddenNoReceipt(t *testing.T) {
	f := newFixture(t, nil)
	cases := []struct {
		name string
		hdr  map[string]string
	}{
		{"admin session", map[string]string{"X-Auth-Request-Email": fixtureAdminEmail}},
		{"participant session", map[string]string{"X-Auth-Request-Email": "alice@ctf.local"}},
		{"X-Auth-Request-User only", map[string]string{"X-Auth-Request-User": "alice"}},
		{"empty-valued X-Auth-Request-Email", map[string]string{"X-Auth-Request-Email": ""}},
		{"lower-cased wire spelling", map[string]string{"x-auth-request-email": fixtureAdminEmail}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := f.exfilReq("03-exfil", "application/json", exfilBody, c.hdr)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body)
			}
			if f.st.HasExfilAny("alice", "03-exfil") {
				t.Fatal("an exfil receipt was recorded despite the 403")
			}
		})
	}
}

// The 403 comes before the catalog checks, so nothing about the request's
// content (unknown / non-exfil challenge, junk body) changes the response.
func TestExfilInternal_ProxyIdentityHeader_ForbiddenBeforeOtherChecks(t *testing.T) {
	f := newFixture(t, nil)
	hdr := map[string]string{"X-Auth-Request-Email": fixtureAdminEmail}
	var first string
	for i, c := range []struct{ cid, body string }{
		{"03-exfil", exfilBody},
		{"99-unknown", exfilBody},
		{"02-evade", exfilBody},
		{"03-exfil", "{"},
		{"03-exfil", ""},
	} {
		w := f.exfilReq(c.cid, "application/json", c.body, hdr)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cid=%s body=%q: status=%d body=%s, want 403", c.cid, c.body, w.Code, w.Body)
		}
		if i == 0 {
			first = w.Body.String()
		} else if w.Body.String() != first {
			t.Fatalf("cid=%s body=%q: response %q differs from %q (content-dependent refusal)", c.cid, c.body, w.Body, first)
		}
	}
}

// Header-less + JSON is the collector forward and is unchanged.
func TestExfilInternal_CollectorPathStillWorks(t *testing.T) {
	f := newFixture(t, nil)
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON"} {
		w := f.exfilReq("03-exfil", ct, exfilBody, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("Content-Type=%q: status=%d body=%s, want 200", ct, w.Code, w.Body)
		}
	}
	if !f.st.HasExfilAny("alice", "03-exfil") {
		t.Fatal("collector-path exfil receipt was not recorded")
	}
}

func TestExfilInternal_NonJSONContentTypeRejected(t *testing.T) {
	f := newFixture(t, nil)
	for _, ct := range []string{"text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", ""} {
		w := f.exfilReq("03-exfil", ct, exfilBody, nil)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type=%q: status=%d body=%s, want 415", ct, w.Code, w.Body)
		}
		if f.st.HasExfilAny("alice", "03-exfil") {
			t.Fatalf("Content-Type=%q: a receipt was recorded despite the 415", ct)
		}
	}
}
