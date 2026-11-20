package scoreboard_test

// ADR-0056 A4f / V105 at the handler: what NewHandler puts in the gauge
// scoreboard_edition_loaded_info{run_id}, read off GET /metrics of the handler it
// assembled. The gauge names a run id only when a Judge is wired AND the run id has
// the form of one; every other wiring reads `none` (fail-closed: platform's reader
// of an event with an answers table FAILs on none). Each case assembles a new handler
// in this process, on the default registry, so "exactly one series after each" is
// also the check that a second assembly replaces the series (a set without the Reset
// leaves two). The run ids are synthetic.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
)

const edGaugeFamily = "scoreboard_edition_loaded_info"

// edGaugeSeries is GET /metrics of h: the whole body and its sample lines of the family.
func edGaugeSeries(t *testing.T, h http.Handler) (string, []string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	var series []string
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, edGaugeFamily) {
			series = append(series, ln)
		}
	}
	return body, series
}

func TestEditionGauge_NewHandlerSetsExactlyOneSeries(t *testing.T) {
	cases := []struct {
		name      string
		withJudge bool
		opts      []scoreboard.Option
		want      string
	}{
		{"no Judge, no run id (no table needed)", false, nil, "none"},
		{"a Judge and its run id (the event table)", true, []scoreboard.Option{scoreboard.WithEditionRunID(ansRun)}, ansRun},
		{"a Judge and the practice run id", true, []scoreboard.Option{scoreboard.WithEditionRunID(edition.PracticeRunID)}, "00000000000000000000000000000000"},
		{"the event table again, after the practice one", true, []scoreboard.Option{scoreboard.WithEditionRunID(ansRun)}, ansRun},
		{"a Judge without a run id", true, nil, "none"},
		{"a Judge with a run id of another form (upper case)", true, []scoreboard.Option{scoreboard.WithEditionRunID(strings.ToUpper("abcdef0123456789abcdef0123456789"))}, "none"},
		{"a Judge with a run id of another length", true, []scoreboard.Option{scoreboard.WithEditionRunID(ansRun[:31])}, "none"},
		{"a run id without a Judge", false, []scoreboard.Option{scoreboard.WithEditionRunID(ansRun)}, "none"},
	}
	for _, c := range cases {
		f := newAnswerFixture(t, c.withJudge, c.opts...)
		body, series := edGaugeSeries(t, f.srv)
		want := edGaugeFamily + `{run_id="` + c.want + `"} 1`
		if len(series) != 1 || series[0] != want {
			t.Errorf("%s: the series of %s = %q, want exactly [%s]", c.name, edGaugeFamily, series, want)
		}
		if strings.Contains(body, ansSecret) {
			t.Errorf("%s: GET /metrics holds a table value", c.name)
		}
	}
}
