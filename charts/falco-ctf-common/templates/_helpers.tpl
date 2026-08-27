{{- /*
  falco-ctf-common — shared named templates (P21 item 5, REFACTORING.md).

  Scope of this step (step1): only the two patterns that were byte-identical
  across charts/{scoreboard,auth-policy,collector} — Pod/container
  securityContext (Invariant I2: runAsUser 65532) and the default-deny
  NetworkPolicy. labels / image helper / kube-dns egress are step2
  (REFACTORING.md P21 item 5 — out of scope here). docs/ctf-user are not
  callers of this library (ctf-user's `challenge` container is intentionally
  root — I2 does not apply — and docs/ttyd/ttyd-proxy use different UIDs; see
  .claude/rules/falco-ctf-app-conventions.md "UID 一覧").

  Every define below takes an EXPLICIT argument (a dict, or the caller's root
  context) rather than reading `.Values` — a library chart's own values.yaml
  is not merged into the caller's values, so reaching into `.Values` here
  would silently resolve against the *caller's* values schema and invite
  drift. Explicit dict args keep the contract visible at the call site.
*/}}

{{- /*
  falco-ctf-common.podSecurityContext — Pod-level securityContext for the
  three Invariant I2 services (scoreboard/auth-policy/collector).

  Arg: a dict. Optional key `fsGroup` (int) — only scoreboard sets this
  (Invariant I3: PVC fsGroup 65532); auth-policy/collector have no volumes
  and never set fsGroup. Emitting it conditionally (rather than always) is
  what keeps this template's output byte-identical to the two shapes that
  existed before extraction.

  Usage:
    securityContext:
      {{- include "falco-ctf-common.podSecurityContext" (dict "fsGroup" 65532) | nindent 8 }}
    securityContext:
      {{- include "falco-ctf-common.podSecurityContext" (dict) | nindent 8 }}
*/}}
{{- define "falco-ctf-common.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
{{- if .fsGroup }}
fsGroup: {{ .fsGroup }}
{{- end }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- /*
  falco-ctf-common.containerSecurityContext — container-level hardening
  (readOnlyRootFilesystem / allowPrivilegeEscalation / capabilities drop
  ALL), identical across scoreboard/auth-policy/collector's single
  container. Arg is unused (define ignores its context) — pass `.` at the
  call site for readability.

  Usage:
    securityContext:
      {{- include "falco-ctf-common.containerSecurityContext" . | nindent 12 }}
*/}}
{{- define "falco-ctf-common.containerSecurityContext" -}}
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
{{- end -}}

{{- /*
  falco-ctf-common.networkPolicy.defaultDeny — the default-deny
  NetworkPolicy (podSelector: {}, both policyTypes) that precedes each
  chart's own scoped `-allow` policy. Structure only — the scoped `-allow`
  policy (ingress/egress rules) stays chart-specific and is NOT covered by
  this template (each chart's audiences differ).

  Arg: a dict with `name` (chart/app name, e.g. "scoreboard") and
  `namespace`. Renders a full standalone NetworkPolicy document — the
  caller is responsible for the `---` document separator before/after it
  and for any file-level comment header.

  Usage:
    {{ include "falco-ctf-common.networkPolicy.defaultDeny" (dict "name" "scoreboard" "namespace" "scoreboard") }}
    ---
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: scoreboard-allow
      ...
*/}}
{{- define "falco-ctf-common.networkPolicy.defaultDeny" -}}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ .name }}-default-deny
  namespace: {{ .namespace }}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
{{- end -}}
