package detect

import (
	"strings"
	"testing"
)

// baseSpec/baseResult build a matching (spec, result) pair; each test then
// perturbs exactly one field to prove acceptResult rejects on ANY single
// mismatch (strict authenticity — the prod path never trusts a pod-produced
// value, so a forged/stale/mislabelled Job can never be accepted).
func baseSpec() JobSpec {
	return JobSpec{
		Namespace: "falco-ctf-grader",
		Name:      "detect-04-detect-deadbeef",
		Labels: map[string]string{
			"app.kubernetes.io/name":      "detect-grader",
			"app.kubernetes.io/component": "grader-job",
			"falco-ctf/challenge":         "04-detect",
		},
	}
}

func baseResult(s JobSpec) JobResult {
	labels := make(map[string]string, len(s.Labels))
	for k, v := range s.Labels {
		labels[k] = v
	}
	return JobResult{
		Namespace: s.Namespace,
		Name:      s.Name,
		Labels:    labels,
		Succeeded: 1,
	}
}

func TestAcceptResult_ExactMatchAccepted(t *testing.T) {
	s := baseSpec()
	if !acceptResult(s, baseResult(s)) {
		t.Fatal("a full identity match must be accepted")
	}
}

func TestAcceptResult_NamespaceMismatchRejected(t *testing.T) {
	s := baseSpec()
	r := baseResult(s)
	r.Namespace = "default"
	if acceptResult(s, r) {
		t.Fatal("a namespace mismatch must be rejected")
	}
}

func TestAcceptResult_NameMismatchRejected(t *testing.T) {
	s := baseSpec()
	r := baseResult(s)
	r.Name = "detect-04-detect-0000cafe" // a different nonce (stale/forged Job)
	if acceptResult(s, r) {
		t.Fatal("a name (nonce) mismatch must be rejected")
	}
}

func TestAcceptResult_LabelMismatchRejected(t *testing.T) {
	s := baseSpec()
	r := baseResult(s)
	r.Labels["falco-ctf/challenge"] = "05-other" // result for a different mission
	if acceptResult(s, r) {
		t.Fatal("a label mismatch (wrong challenge) must be rejected")
	}
}

func TestAcceptResult_MissingLabelRejected(t *testing.T) {
	s := baseSpec()
	r := baseResult(s)
	delete(r.Labels, "app.kubernetes.io/name")
	if acceptResult(s, r) {
		t.Fatal("a missing expected label must be rejected")
	}
}

// acceptResult itself does NOT gate on Succeeded (the caller does that
// separately for the verdict); but a full identity match with Succeeded<1 must
// still be *accepted by acceptResult* — the identity is authentic, the verdict
// is decided elsewhere. This documents the split so a refactor does not fold the
// success gate into acceptResult and change semantics.
func TestAcceptResult_IdentityOnly_SucceededNotChecked(t *testing.T) {
	s := baseSpec()
	r := baseResult(s)
	r.Succeeded = 0
	if !acceptResult(s, r) {
		t.Fatal("acceptResult checks identity only; Succeeded is the caller's verdict gate")
	}
}

func TestJobName_Bounded(t *testing.T) {
	name := jobName("04-detect", "deadbeefcafef00d")
	if !strings.HasPrefix(name, "detect-04-detect-") {
		t.Fatalf("job name must carry the challenge + nonce, got %q", name)
	}
	// A pathologically long challenge id must not blow past the RFC1123 63-char
	// label cap, and must not end in a dash.
	long := jobName(strings.Repeat("x", 200), "deadbeefcafef00d")
	if len(long) > 63 {
		t.Fatalf("job name must be <=63 chars, got %d (%q)", len(long), long)
	}
	if strings.HasSuffix(long, "-") {
		t.Fatalf("job name must not end in a dash, got %q", long)
	}
}

func TestSanitizeLabel(t *testing.T) {
	cases := map[string]string{
		"04-detect":       "04-detect",
		"04_Detect":       "04-detect",     // uppercase folded, `_` → `-`
		"a/b:c d":         "a-b-c-d",        // metachars mapped to dash
		"--leading-trail-": "leading-trail", // trimmed of surrounding dashes
	}
	for in, want := range cases {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
	// Bounded length.
	if got := sanitizeLabel(strings.Repeat("a", 100)); len(got) > 40 {
		t.Fatalf("sanitizeLabel must cap at 40 chars, got %d", len(got))
	}
}

func TestExpectedLabels_IncludesChallenge(t *testing.T) {
	got := expectedLabels("04-detect")
	if got["falco-ctf/challenge"] != "04-detect" {
		t.Fatalf("expected labels must pin the challenge id, got %v", got)
	}
	if got["app.kubernetes.io/name"] != "detect-grader" {
		t.Fatalf("expected labels must carry the grader name, got %v", got)
	}
}
