package ingest_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ingest"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
)

// The internal-only contract of POST /falco/events (the admin ingress
// catch-all also routes this path to an admin BROWSER, where oauth2-proxy
// stamps X-Auth-Request-*; falcosidekick never does): any X-Auth-Request-*
// header => 403 before everything else, and a non-JSON Content-Type => 415.
// Neither may record a rule fire or taint anything, in ANY secret mode —
// production runs webhookSecretMode=warn, where a secret-less request is
// otherwise processed.

const browserPathBody = `{"rule":"Detect Outbound Connection","priority":"Warning","output_fields":{"k8s.ns.name":"ctf-alice","k8s.pod.name":"workspace","container.image.repository":"falco-ctf/challenge"}}`

// postRaw POSTs browserPathBody with the given Content-Type ("" = none) and
// extra headers.
func postRaw(t *testing.T, url, contentType string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/falco/events", bytes.NewReader([]byte(browserPathBody)))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else {
		// net/http would otherwise send none for a bytes.Reader body; make the
		// absence explicit.
		req.Header.Del("Content-Type")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /falco/events: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestReceive_ProxyIdentityHeader_ForbiddenAndNothingRecorded(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	nowUnix := float64(clock().UnixNano()) / 1e9
	const secret = "correct-horse-battery-staple"

	modes := []struct {
		name string
		mode ingest.SecretMode
	}{
		{"off", ingest.SecretModeOff},
		{"warn (production)", ingest.SecretModeWarn},
		{"enforce", ingest.SecretModeEnforce},
	}
	headers := []struct {
		name string
		hdr  map[string]string
	}{
		{"admin session", map[string]string{"X-Auth-Request-Email": "admin@ctf.local"}},
		{"participant session", map[string]string{"X-Auth-Request-Email": "alice@ctf.local"}},
		{"X-Auth-Request-User only", map[string]string{"X-Auth-Request-User": "alice"}},
		{"empty-valued X-Auth-Request-Email", map[string]string{"X-Auth-Request-Email": ""}},
		// Even a CORRECT shared secret does not rescue a header-bearing request:
		// the browser path is refused outright, not authenticated.
		{"header plus the correct shared secret", map[string]string{"X-Auth-Request-Email": "admin@ctf.local", ingest.SharedSecretHeader: secret}},
	}
	for _, m := range modes {
		for _, h := range headers {
			t.Run(m.name+"/"+h.name, func(t *testing.T) {
				srv, s := newFixtureWithSecret(t, clock, secret, m.mode)
				forbiddenBefore := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("forbidden"))
				acceptedBefore := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted"))

				resp := postRaw(t, srv.URL, "application/json", h.hdr)
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", resp.StatusCode)
				}
				if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 0 {
					t.Fatalf("RecentRuleFires = %v, want empty (a refused request must record nothing)", fires)
				}
				if dirty := s.DirtyRules("alice", "02-evade"); len(dirty) != 0 {
					t.Fatalf("DirtyRules = %v, want empty (the grader must never run on a refused request)", dirty)
				}
				if got := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("forbidden")); got != forbiddenBefore+1 {
					t.Fatalf(`"forbidden" metric = %v, want %v`, got, forbiddenBefore+1)
				}
				if got := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("accepted")); got != acceptedBefore {
					t.Fatalf(`"accepted" metric = %v, want unchanged at %v`, got, acceptedBefore)
				}
			})
		}
	}
}

// Header-less + JSON is falcosidekick's real shape (its client sends
// "application/json; charset=utf-8" and the platform only adds the shared
// secret header) and keeps being processed exactly as before — in the
// production warn mode WITHOUT a secret, and with the secret.
func TestReceive_HeaderlessJSON_StillProcessed(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	nowUnix := float64(clock().UnixNano()) / 1e9

	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON"} {
		t.Run(ct, func(t *testing.T) {
			srv, s := newFixtureWithSecret(t, clock, "correct-horse-battery-staple", ingest.SecretModeWarn)
			resp := postRaw(t, srv.URL, ct, map[string]string{ingest.SharedSecretHeader: "correct-horse-battery-staple"})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 1 {
				t.Fatalf("RecentRuleFires = %v, want exactly 1", fires)
			}
		})
	}
}

func TestReceive_NonJSONContentType_415AndNothingRecorded(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	nowUnix := float64(clock().UnixNano()) / 1e9

	// The Content-Types a cross-site no-cors POST can carry, plus none at all
	// and near-misses.
	for _, ct := range []string{"text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", "application/json-seq", ""} {
		t.Run(strings.ReplaceAll(ct, "/", "_")+"|", func(t *testing.T) {
			// warn mode with no secret sent: the production posture in which this
			// request would otherwise be processed.
			srv, s := newFixtureWithSecret(t, clock, "correct-horse-battery-staple", ingest.SecretModeWarn)
			before := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("unsupported_media_type"))

			resp := postRaw(t, srv.URL, ct, nil)
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("Content-Type=%q: status = %d, want 415", ct, resp.StatusCode)
			}
			if fires := s.RecentRuleFires("alice", nowUnix, 3600); len(fires) != 0 {
				t.Fatalf("RecentRuleFires = %v, want empty", fires)
			}
			if dirty := s.DirtyRules("alice", "02-evade"); len(dirty) != 0 {
				t.Fatalf("DirtyRules = %v, want empty", dirty)
			}
			if got := testutil.ToFloat64(metrics.FalcoEventsReceived.WithLabelValues("unsupported_media_type")); got != before+1 {
				t.Fatalf(`"unsupported_media_type" metric = %v, want %v`, got, before+1)
			}
		})
	}
}
