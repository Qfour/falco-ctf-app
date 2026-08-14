package detect

// clientgo.go is the ONLY file in this package that imports client-go /
// apimachinery. It implements the JobClient port (k8sjob.go) with a real
// in-cluster Kubernetes client: create a per-submission batch/v1 Job with the
// hardened pod template, watch it to a terminal state, and read back the
// observed identity + status for the strict authenticity check in acceptResult.
//
// Everything security-relevant is expressed in the JobSpec (k8sjob.go) and the
// pod template built here, NOT trusted to the grader pod:
//   - automountServiceAccountToken:false, backoffLimit:0, activeDeadlineSeconds,
//     ttlSecondsAfterFinished, restartPolicy:Never;
//   - non-root securityContext (runAsNonRoot + runAsUser 65532, drop ALL caps,
//     no privilege escalation, read-only rootfs, seccomp RuntimeDefault);
//   - the participant condition is delivered via a file mount (an emptyDir the
//     scoreboard populates is NOT possible cross-pod; instead the condition is
//     passed through a per-Job Secret mounted read-only at ConditionMountPath —
//     never argv/env), and the capture dir is a read-only mount baked into the
//     grader image (no participant-controlled path);
//   - no network is enforced by a deny-all NetworkPolicy that platform supplies
//     for the grader namespace (design §3.3/§3.4) — the app cannot set
//     `--network none` on a Job, so this is a platform contract, asserted here
//     only by NOT granting any network need.
//
// The verdict is decided by K8sJob.Grade from res.Succeeded (never from a
// pod-produced value); EvasionFires/BenignFires are read from the authenticated
// Job's pod terminationMessage for UI feedback ONLY.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// clientGoJobClient is the prod JobClient: it drives the Kubernetes Batch API
// via client-go using the in-cluster ServiceAccount. It is constructed only when
// DETECT_RUNNER=k8s (main.go); dev/CI use LocalExec instead.
type clientGoJobClient struct {
	cs kubernetes.Interface
}

// NewInClusterJobClient builds a JobClient from the in-cluster config (the
// scoreboard pod's mounted ServiceAccount token + the kube API from
// KUBERNETES_SERVICE_HOST/PORT). It fails closed if there is no in-cluster
// config (e.g. run outside a pod) so a misconfigured DETECT_RUNNER=k8s cannot
// silently degrade to "no grading".
func NewInClusterJobClient() (JobClient, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("detect: in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("detect: kube client: %w", err)
	}
	return &clientGoJobClient{cs: cs}, nil
}

// conditionSecretName derives the per-Job Secret name from the Job name so it is
// 1:1 with the submission and cleaned up alongside the Job.
func conditionSecretName(jobName string) string {
	name := jobName + "-cond"
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-")
}

// Create submits the per-submission grader Job (and its condition Secret). The
// condition is carried in this Secret and mounted read-only at
// spec.ConditionMountPath — never argv/env — matching the untrusted-input
// hardening in the design (§3.3). The Secret and Job share the nonce'd name and
// labels so the strict authenticity check (acceptResult) still holds.
//
// NOTE: the participant condition is passed to Create via the spec's Name-scoped
// Secret; K8sJob.Grade delivers the condition text out-of-band. To keep JobSpec
// client-go-free, the condition is threaded through here via ConditionText.
func (c *clientGoJobClient) Create(ctx context.Context, spec JobSpec) error {
	// 1) Per-Job Secret carrying the condition as a file (mounted RO at
	//    ConditionMountPath). Owner-less here; deleted explicitly in Delete and
	//    also GC'd by the namespace's lifecycle. No condition ever hits argv/env.
	secretName := conditionSecretName(spec.Name)
	condFileName := lastPathElem(spec.ConditionMountPath) // e.g. "condition"
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: spec.Namespace,
			Labels:    spec.Labels,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{condFileName: []byte(spec.ConditionText)},
	}
	if _, err := c.cs.CoreV1().Secrets(spec.Namespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("detect: create condition secret: %w", err)
	}

	job := c.buildJob(spec, secretName, condFileName)
	if _, err := c.cs.BatchV1().Jobs(spec.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		// Best-effort cleanup of the orphan Secret so a failed Create does not leak.
		_ = c.cs.CoreV1().Secrets(spec.Namespace).Delete(context.WithoutCancel(ctx), secretName, metav1.DeleteOptions{})
		return fmt.Errorf("detect: create job: %w", err)
	}
	return nil
}

// buildJob translates the client-go-free JobSpec into a hardened batch/v1 Job.
// Every DoS/isolation control is set here so it is enforced identically for
// every submission (design §3.3). The pod mounts:
//   - the condition Secret read-only at the ConditionMountPath dir;
//   - nothing writable except a small emptyDir /tmp (read-only rootfs otherwise).
//
// The grader image bakes the captures and the entrypoint; the app supplies only
// the challenge id (as an env for the entrypoint to select the capture pair) and
// the condition file.
func (c *clientGoJobClient) buildJob(spec JobSpec, secretName, condFileName string) *batchv1.Job {
	backoff := spec.BackoffLimit
	deadline := spec.ActiveDeadlineSeconds
	ttl := spec.TTLSecondsAfterFinished
	automount := spec.AutomountServiceAccountToken // MUST be false
	condDir := dirOfPath(spec.ConditionMountPath)  // e.g. "/input"

	nonRoot := true
	noEsc := false
	readOnlyRoot := true
	var uid int64 = 65532
	var gid int64 = 65532

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name,
			Namespace: spec.Namespace,
			Labels:    spec.Labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			ActiveDeadlineSeconds:   &deadline,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: spec.Labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: &automount,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &nonRoot,
						RunAsUser:    &uid,
						RunAsGroup:   &gid,
						FSGroup:      &gid,
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:  "grader",
						Image: spec.Image,
						// The entrypoint (in the grader image) selects the capture pair
						// from CHALLENGE_ID and reads the condition from the mounted file.
						// The condition is NEVER passed via argv/env (untrusted-input
						// hardening); only the challenge id (operator-controlled) is.
						Env: []corev1.EnvVar{
							{Name: "CHALLENGE_ID", Value: spec.ChallengeID},
							{Name: "CONDITION_FILE", Value: spec.ConditionMountPath},
						},
						SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot:             &nonRoot,
							RunAsUser:                &uid,
							AllowPrivilegeEscalation: &noEsc,
							ReadOnlyRootFilesystem:   &readOnlyRoot,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("256Mi"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "condition", MountPath: condDir, ReadOnly: true},
							{Name: "tmp", MountPath: "/tmp"},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "condition",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: secretName,
									Items:      []corev1.KeyToPath{{Key: condFileName, Path: condFileName}},
								},
							},
						},
						{
							Name:         "tmp",
							VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
						},
					},
				},
			},
		},
	}
}

// WaitResult polls the Job until it reaches a terminal state (Complete or
// Failed) or ctx is cancelled / deadline elapses, then returns the observed
// identity + status. Counts (for UI feedback only) are parsed from the pod's
// terminationMessage of the authenticated Job.
func (c *clientGoJobClient) WaitResult(ctx context.Context, namespace, name string) (JobResult, error) {
	var res JobResult
	// Poll every 500ms; the Job's own activeDeadlineSeconds bounds the worst case,
	// and the caller's ctx (request-scoped) is the hard ceiling.
	err := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		job, err := c.cs.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("detect: get job: %w", err)
		}
		terminal := false
		for _, cond := range job.Status.Conditions {
			if (cond.Type == batchv1.JobComplete || cond.Type == batchv1.JobFailed) && cond.Status == corev1.ConditionTrue {
				terminal = true
				break
			}
		}
		if !terminal {
			return false, nil
		}
		res = JobResult{
			Namespace: job.Namespace,
			Name:      job.Name,
			Labels:    job.Labels,
			Succeeded: job.Status.Succeeded,
		}
		// Counts (UI feedback only) from the pod's terminationMessage. Best-effort:
		// a parse miss leaves counts at 0 and never affects the verdict.
		if ef, bf, ok := c.readCounts(ctx, namespace, name); ok {
			res.EvasionFires = ef
			res.BenignFires = bf
		}
		return true, nil
	})
	if err != nil {
		return JobResult{}, err
	}
	return res, nil
}

// readCounts fetches the grader pod for the Job and parses its terminated
// container's terminationMessage as {"evasionFires":N,"benignFires":M}. This is
// UI-feedback-only; it is read from the authenticated Job's own pod and never
// decides the verdict (K8sJob.Grade uses Succeeded).
func (c *clientGoJobClient) readCounts(ctx context.Context, namespace, jobName string) (int, int, bool) {
	pods, err := c.cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil || len(pods.Items) == 0 {
		return 0, 0, false
	}
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Terminated == nil {
				continue
			}
			msg := cs.State.Terminated.Message
			var out struct {
				EvasionFires int `json:"evasionFires"`
				BenignFires  int `json:"benignFires"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(msg)), &out); err == nil {
				return out.EvasionFires, out.BenignFires, true
			}
		}
	}
	return 0, 0, false
}

// Delete removes the Job (foreground propagation, so its pods go too) and the
// condition Secret. Errors are non-fatal to grading (ttlSecondsAfterFinished and
// the namespace lifecycle also cover cleanup).
func (c *clientGoJobClient) Delete(ctx context.Context, namespace, name string) error {
	fg := metav1.DeletePropagationForeground
	_ = c.cs.BatchV1().Jobs(namespace).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &fg})
	_ = c.cs.CoreV1().Secrets(namespace).Delete(ctx, conditionSecretName(name), metav1.DeleteOptions{})
	return nil
}

// lastPathElem returns the final element of a slash path (the file name).
func lastPathElem(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dirOfPath returns the directory of a slash path (everything before the final
// element); "/" if there is no parent.
func dirOfPath(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "/"
}
