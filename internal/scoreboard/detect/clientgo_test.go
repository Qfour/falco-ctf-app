package detect

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// sampleSpec is a representative JobSpec the K8sJob runner would hand to the
// JobClient, matching what Grade builds.
func sampleSpec() JobSpec {
	return JobSpec{
		Namespace:                    "falco-ctf-grader",
		Name:                         "detect-04-detect-deadbeef",
		Labels:                       expectedLabels("04-detect"),
		Image:                        "reg/detect-grader@sha256:abc",
		ChallengeID:                  "04-detect",
		ConditionText:                "open_read and fd.name endswith \"/shadow\"",
		ConditionMountPath:           "/input/condition",
		ActiveDeadlineSeconds:        20,
		BackoffLimit:                 0,
		TTLSecondsAfterFinished:      60,
		AutomountServiceAccountToken: false,
	}
}

// TestCreate_HardenedJobAndSecret asserts the adapter renders every DoS /
// isolation control from the design (§3.3) into the batch/v1 Job, and that the
// UNTRUSTED condition is delivered via a Secret-backed file mount — never argv
// or env. A regression here would weaken the sandbox for untrusted Falco exec.
func TestCreate_HardenedJobAndSecret(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := &clientGoJobClient{cs: cs}
	spec := sampleSpec()

	if err := c.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	job, err := cs.BatchV1().Jobs(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get created job: %v", err)
	}

	// --- Job-level DoS controls ---
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		t.Errorf("BackoffLimit must be 0 (never retry a graded submission), got %v", job.Spec.BackoffLimit)
	}
	if job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 20 {
		t.Errorf("ActiveDeadlineSeconds must be 20, got %v", job.Spec.ActiveDeadlineSeconds)
	}
	if job.Spec.TTLSecondsAfterFinished == nil || *job.Spec.TTLSecondsAfterFinished != 60 {
		t.Errorf("TTLSecondsAfterFinished must be 60, got %v", job.Spec.TTLSecondsAfterFinished)
	}

	pod := job.Spec.Template.Spec
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restartPolicy must be Never, got %v", pod.RestartPolicy)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Errorf("automountServiceAccountToken must be false, got %v", pod.AutomountServiceAccountToken)
	}

	// --- pod securityContext: non-root UID 65532 (I2 alignment) ---
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsUser == nil || *pod.SecurityContext.RunAsUser != 65532 {
		t.Errorf("pod runAsUser must be 65532, got %v", pod.SecurityContext)
	}
	if pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Errorf("pod runAsNonRoot must be true")
	}

	// --- container securityContext ---
	if len(pod.Containers) != 1 {
		t.Fatalf("expected exactly one container, got %d", len(pod.Containers))
	}
	ctr := pod.Containers[0]
	sc := ctr.SecurityContext
	if sc == nil {
		t.Fatal("container securityContext must be set")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("readOnlyRootFilesystem must be true")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("allowPrivilegeEscalation must be false")
	}
	if sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("capabilities must drop ALL, got %v", sc.Capabilities)
	}
	if sc.RunAsUser == nil || *sc.RunAsUser != 65532 {
		t.Errorf("container runAsUser must be 65532, got %v", sc.RunAsUser)
	}

	// --- resource caps present ---
	if ctr.Resources.Limits.Cpu().IsZero() || ctr.Resources.Limits.Memory().IsZero() {
		t.Error("cpu+memory limits must be set")
	}

	// --- untrusted condition delivered via FILE, never argv/env ---
	for _, e := range ctr.Env {
		if e.Value == spec.ConditionText {
			t.Fatalf("condition MUST NOT appear in env (%s); untrusted-input hardening", e.Name)
		}
	}
	for _, a := range ctr.Args {
		if a == spec.ConditionText {
			t.Fatal("condition MUST NOT appear in argv; untrusted-input hardening")
		}
	}
	// The entrypoint receives only the operator-controlled challenge id + file path.
	var sawChallengeEnv bool
	for _, e := range ctr.Env {
		if e.Name == "CHALLENGE_ID" && e.Value == spec.ChallengeID {
			sawChallengeEnv = true
		}
	}
	if !sawChallengeEnv {
		t.Error("entrypoint must receive CHALLENGE_ID env")
	}

	// The condition Secret exists and holds the condition under the mount file name.
	secName := conditionSecretName(spec.Name)
	sec, err := cs.CoreV1().Secrets(spec.Namespace).Get(context.Background(), secName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("condition secret must be created: %v", err)
	}
	if got := string(sec.Data["condition"]); got != spec.ConditionText {
		t.Errorf("condition secret must carry the condition, got %q", got)
	}
	// The Secret is mounted read-only into the pod at the condition dir.
	var mountRO bool
	for _, m := range ctr.VolumeMounts {
		if m.MountPath == "/input" && m.ReadOnly {
			mountRO = true
		}
	}
	if !mountRO {
		t.Error("condition dir must be mounted read-only at /input")
	}
}

// TestWaitResult_CompleteReadsIdentityAndCounts drives a Job to a terminal
// Complete state with a pod carrying a JSON terminationMessage, and asserts
// WaitResult returns the observed identity + Succeeded and parses the
// UI-feedback counts.
func TestWaitResult_CompleteReadsIdentityAndCounts(t *testing.T) {
	spec := sampleSpec()
	// Seed a terminal Job + its pod so the poll's first Get sees a terminal state.
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: spec.Name, Namespace: spec.Namespace, Labels: spec.Labels},
		Status: batchv1.JobStatus{
			Succeeded:  1,
			Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name + "-abc",
			Namespace: spec.Namespace,
			Labels:    map[string]string{"job-name": spec.Name},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					Message: `{"evasionFires":2,"benignFires":0}`,
				}},
			}},
		},
	}
	cs := fake.NewSimpleClientset(job, pod)
	c := &clientGoJobClient{cs: cs}

	res, err := c.WaitResult(context.Background(), spec.Namespace, spec.Name)
	if err != nil {
		t.Fatalf("WaitResult: %v", err)
	}
	if res.Namespace != spec.Namespace || res.Name != spec.Name {
		t.Errorf("identity mismatch: got %s/%s", res.Namespace, res.Name)
	}
	if res.Succeeded != 1 {
		t.Errorf("Succeeded must be 1, got %d", res.Succeeded)
	}
	if res.EvasionFires != 2 || res.BenignFires != 0 {
		t.Errorf("counts from terminationMessage: got evasion=%d benign=%d", res.EvasionFires, res.BenignFires)
	}
	// The result identity must satisfy the strict authenticity predicate against
	// the spec we created — the whole point of the prod path.
	if !acceptResult(spec, res) {
		t.Error("authentic terminal Job result must pass acceptResult")
	}
}

// TestWaitResult_FailedReturnsSucceededZero asserts a Failed Job is terminal and
// reported with Succeeded=0, so K8sJob.Grade maps it to invalid (fail-closed) —
// never a solve.
func TestWaitResult_FailedReturnsSucceededZero(t *testing.T) {
	spec := sampleSpec()
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: spec.Name, Namespace: spec.Namespace, Labels: spec.Labels},
		Status: batchv1.JobStatus{
			Succeeded:  0,
			Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}},
		},
	}
	cs := fake.NewSimpleClientset(job)
	c := &clientGoJobClient{cs: cs}

	res, err := c.WaitResult(context.Background(), spec.Namespace, spec.Name)
	if err != nil {
		t.Fatalf("WaitResult: %v", err)
	}
	if res.Succeeded != 0 {
		t.Errorf("failed job must report Succeeded=0, got %d", res.Succeeded)
	}
}

// TestDelete_RemovesJobAndSecret asserts cleanup removes both the Job and its
// condition Secret so a graded submission leaves no residue.
func TestDelete_RemovesJobAndSecret(t *testing.T) {
	spec := sampleSpec()
	cs := fake.NewSimpleClientset()
	c := &clientGoJobClient{cs: cs}
	if err := c.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.Delete(context.Background(), spec.Namespace, spec.Name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.BatchV1().Jobs(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{}); err == nil {
		t.Error("job must be deleted")
	}
	if _, err := cs.CoreV1().Secrets(spec.Namespace).Get(context.Background(), conditionSecretName(spec.Name), metav1.GetOptions{}); err == nil {
		t.Error("condition secret must be deleted")
	}
}

// TestPathHelpers pins the file/dir splitting used to mount the condition file.
func TestPathHelpers(t *testing.T) {
	if got := lastPathElem("/input/condition"); got != "condition" {
		t.Errorf("lastPathElem = %q", got)
	}
	if got := dirOfPath("/input/condition"); got != "/input" {
		t.Errorf("dirOfPath = %q", got)
	}
	if got := dirOfPath("/condition"); got != "/" {
		t.Errorf("dirOfPath root = %q", got)
	}
}
