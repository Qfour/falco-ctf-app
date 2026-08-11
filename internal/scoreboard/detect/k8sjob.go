package detect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// K8sJob is the prod DetectRunner: it creates a per-submission Kubernetes Job in
// a dedicated grader namespace, waits for completion, and accepts the result
// ONLY on a strict authenticity match (design §3.1/§3.3).
//
// This file owns the SECURITY-CRITICAL, client-go-free logic so it is unit
// -testable today without pulling the (large) client-go dependency tree into
// this public repo before the dep is ratified (VP/security-lead — see the report
// and design §3.4). The actual apimachinery calls are behind the JobClient port;
// a thin client-go adapter implements it once the dependency is approved. Nothing
// here trusts a value produced INSIDE the grader pod:
//
//   - the Job NAME carries a random nonce (jobName) so a stale/forged Job cannot
//     be mistaken for this submission's;
//   - the result is accepted ONLY when the observed Job matches, ALL of:
//     namespace == the grader namespace, name == the exact nonce'd name we
//     created, labels ⊇ the expected label set, and status.succeeded >= 1
//     (acceptResult). We do NOT read a fire-count from the pod's output as the
//     verdict source of truth on the prod path — succeeded means the in-image
//     entrypoint's own compile-gate + replay passed its PASS criteria. (Counts
//     for UI feedback, when surfaced, come from the same authenticated Job's
//     terminationMessage / result, never from an unauthenticated stream.)
//   - Job spec: automountServiceAccountToken:false, activeDeadlineSeconds,
//     backoffLimit:0, ttlSecondsAfterFinished, non-root/read-only/drop-ALL, no
//     network (deny-all NetworkPolicy supplied by platform).
//
// The falco image is a digest-pinned placeholder here; the real digest is
// supplied by platform (helmfile) — app must not bake a floating tag (I4/I5).
type K8sJob struct {
	cat       catalog.Catalog
	namespace string // dedicated grader namespace (platform-provisioned)
	image     string // digest-pinned detect-grader image (platform-supplied value)
	client    JobClient
	nonce     func() string // injectable for deterministic tests
}

// JobClient is the minimal port over the Kubernetes Batch API the runner needs.
// A client-go adapter (deferred until the dependency is ratified) implements it;
// tests use a fake. Keeping the runner behind this port means the authenticity /
// spec logic is exercised without apimachinery.
type JobClient interface {
	// Create submits the Job described by spec and returns nothing on success.
	Create(ctx context.Context, spec JobSpec) error
	// WaitResult blocks until the named Job in namespace terminates (or ctx is
	// cancelled / the Job's activeDeadlineSeconds elapses) and returns the
	// observed terminal Job identity + status for authenticity checking.
	WaitResult(ctx context.Context, namespace, name string) (JobResult, error)
	// Delete removes the Job (best-effort cleanup; ttlSecondsAfterFinished also
	// covers it). Errors are non-fatal to grading.
	Delete(ctx context.Context, namespace, name string) error
}

// JobSpec is the client-go-free description of the grader Job the runner asks
// the JobClient to create. The adapter translates it into a batchv1.Job with the
// hardened pod template. Every DoS/isolation control (design §3.3) is expressed
// here so it is enforced identically regardless of adapter.
type JobSpec struct {
	Namespace                    string
	Name                         string            // nonce'd; the authenticity anchor
	Labels                       map[string]string // expected label set (authenticity)
	Image                        string            // digest-pinned grader image
	ChallengeID                  string            // arg to the entrypoint
	ConditionMountPath           string            // condition delivered via a file, never argv/env
	ActiveDeadlineSeconds        int64             // ~20s hard cap
	BackoffLimit                 int32             // 0 — never retry a graded submission
	TTLSecondsAfterFinished      int32             // GC the pod shortly after finish
	AutomountServiceAccountToken bool              // MUST be false
}

// JobResult is the observed terminal identity + status of a Job, as reported by
// the JobClient. Its fields are checked against what we created (acceptResult):
// nothing here is trusted until that match passes.
type JobResult struct {
	Namespace string
	Name      string
	Labels    map[string]string
	Succeeded int32
	// EvasionFires/BenignFires are surfaced for UI feedback ONLY, and ONLY read
	// from the authenticated Job's result (e.g. terminationMessage). They never
	// decide the verdict — Succeeded does — so a tampered count cannot force a
	// solve.
	EvasionFires int
	BenignFires  int
}

// NewK8sJob builds the prod runner. namespace is the grader namespace; image is
// the platform-supplied digest-pinned grader image reference.
func NewK8sJob(cat catalog.Catalog, namespace, image string, client JobClient) *K8sJob {
	return &K8sJob{
		cat:       cat,
		namespace: namespace,
		image:     image,
		client:    client,
		nonce:     defaultNonce,
	}
}

func defaultNonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Grade implements scoring.DetectRunner via a per-submission Job. On the prod
// path the in-image entrypoint runs the compile gate + replay and the PASS
// criterion; a succeeded Job means the participant condition detected the
// evasion with zero benign false positives. A compile failure is a NON-succeeded
// terminal Job whose result marks invalid — surfaced as invalid=true so the
// Grader returns DetectInvalidCondition (not an infra error).
func (k *K8sJob) Grade(ctx context.Context, cid, condition string) (evasionFires, benignFires int, invalid bool, err error) {
	if len(condition) > MaxConditionBytes {
		return 0, 0, true, nil
	}
	ch, ok := k.cat[cid]
	if !ok {
		return 0, 0, false, fmt.Errorf("detect: unknown challenge %q", cid)
	}
	if ch.Type != "detect" || ch.Detect == nil {
		return 0, 0, false, fmt.Errorf("detect: challenge %q is not a detect challenge", cid)
	}

	name := jobName(cid, k.nonce())
	labels := expectedLabels(cid)
	spec := JobSpec{
		Namespace:                    k.namespace,
		Name:                         name,
		Labels:                       labels,
		Image:                        k.image,
		ChallengeID:                  cid,
		ConditionMountPath:           "/input/condition", // file, never argv/env
		ActiveDeadlineSeconds:        20,
		BackoffLimit:                 0,
		TTLSecondsAfterFinished:      60,
		AutomountServiceAccountToken: false,
	}

	if err := k.client.Create(ctx, spec); err != nil {
		return 0, 0, false, fmt.Errorf("detect: create job: %w", err)
	}
	// Best-effort cleanup regardless of outcome (ttl also covers it).
	defer func() { _ = k.client.Delete(context.WithoutCancel(ctx), k.namespace, name) }()

	res, err := k.client.WaitResult(ctx, k.namespace, name)
	if err != nil {
		return 0, 0, false, fmt.Errorf("detect: wait job: %w", err)
	}

	// STRICT authenticity: accept the result only on a full identity + status
	// match against what we created. Anything else is treated as an infra error
	// (never a verdict) so a forged / mismatched Job can never solve.
	if !acceptResult(spec, res) {
		return 0, 0, false, fmt.Errorf("detect: job result authenticity check failed for %s/%s", k.namespace, name)
	}
	if res.Succeeded >= 1 {
		// PASS: entrypoint's own compile-gate + replay + PASS criterion held.
		return res.EvasionFires, res.BenignFires, false, nil
	}
	// Terminal but not succeeded. The entrypoint distinguishes a compile failure
	// (invalid) from a graded miss/FP via the result counts on the same
	// authenticated Job: fires are 0/… only meaningful when Succeeded, so a
	// non-succeeded Job is reported as invalid here on the app side ONLY when the
	// entrypoint could not compile the condition. Without a richer status channel
	// we conservatively map a non-succeeded terminal Job to invalid=true (no
	// solve, participant told to fix the condition). A future entrypoint can
	// encode missed/FP vs invalid in the terminationMessage; until then the
	// verdict never over-credits (fail-closed).
	return 0, 0, true, nil
}

// jobName builds the nonce'd Job name. RFC1123-label-safe (lowercase, dashes),
// bounded length. The nonce is the anti-replay/forge anchor.
func jobName(cid, nonce string) string {
	base := "detect-" + sanitizeLabel(cid) + "-" + nonce
	if len(base) > 63 {
		base = base[:63]
	}
	return strings.TrimRight(base, "-")
}

// expectedLabels is the label set we stamp on the Job and require on the
// observed result. Includes the challenge id so a result for a different mission
// cannot be accepted.
func expectedLabels(cid string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "detect-grader",
		"app.kubernetes.io/component": "grader-job",
		"falco-ctf/challenge":         sanitizeLabel(cid),
	}
}

// acceptResult is the STRICT result-authenticity predicate. ALL must hold:
// namespace, exact name, ⊇ expected labels, — the caller separately gates on
// Succeeded for the verdict. A single mismatch rejects the result.
func acceptResult(spec JobSpec, res JobResult) bool {
	if res.Namespace != spec.Namespace {
		return false
	}
	if res.Name != spec.Name {
		return false
	}
	for k, want := range spec.Labels {
		if got, ok := res.Labels[k]; !ok || got != want {
			return false
		}
	}
	return true
}

// sanitizeLabel maps a challenge id to an RFC1123-label-safe token (lowercase
// alnum + dash). Unexpected chars are dropped so a crafted cid cannot inject
// label/name metacharacters.
func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
