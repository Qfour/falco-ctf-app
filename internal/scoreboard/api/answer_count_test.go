package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
)

// ADR-0056 D5: countAnswer maps the Grader's {Status, Newly} to the outcome series
// and, on Newly alone, the solve. The table includes the self-repair path (D5 5):
// the write that follows the last correct answer failed, so the next submission
// comes back already-correct with Newly = true: it is an answer_already_correct
// AND the one solve; the submission after that is an answer_already_correct only.
func TestCountAnswer_StatusAndNewly(t *testing.T) {
	const label = "95-count-test"
	series := func() map[string]float64 {
		out := map[string]float64{"solves": testutil.ToFloat64(metrics.SolvesTotal.WithLabelValues(label, solveKindInvestigate))}
		for _, o := range []string{outcomeAnswerCorrect, outcomeAnswerIncorrect, outcomeAnswerExhausted, outcomeAnswerAlreadyCorrect, outcomeAnswerStoreError} {
			out[o] = testutil.ToFloat64(metrics.SubmissionsTotal.WithLabelValues(label, o))
		}
		return out
	}
	cases := []struct {
		name string
		res  scoring.AnswerResult
		want map[string]float64
	}{
		{"correct, solving", scoring.AnswerResult{Status: scoring.AnswerCorrect, Newly: true}, map[string]float64{outcomeAnswerCorrect: 1, "solves": 1}},
		{"correct, not solving", scoring.AnswerResult{Status: scoring.AnswerCorrect}, map[string]float64{outcomeAnswerCorrect: 1}},
		{"incorrect", scoring.AnswerResult{Status: scoring.AnswerIncorrect}, map[string]float64{outcomeAnswerIncorrect: 1}},
		{"exhausted", scoring.AnswerResult{Status: scoring.AnswerExhausted}, map[string]float64{outcomeAnswerExhausted: 1}},
		{"already-correct completing a solve whose write had failed (self-repair)", scoring.AnswerResult{Status: scoring.AnswerAlreadyCorrect, Newly: true}, map[string]float64{outcomeAnswerAlreadyCorrect: 1, "solves": 1}},
		{"already-correct after that", scoring.AnswerResult{Status: scoring.AnswerAlreadyCorrect}, map[string]float64{outcomeAnswerAlreadyCorrect: 1}},
		{"a status the Grader does not have moves no outcome", scoring.AnswerResult{Status: "bogus"}, nil},
	}
	h := &Handler{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := series()
			h.countAnswer(label, c.res)
			after := series()
			for k := range after {
				if got := after[k] - before[k]; got != c.want[k] {
					t.Errorf("%s moved by %v, want %v", k, got, c.want[k])
				}
			}
		})
	}
}
