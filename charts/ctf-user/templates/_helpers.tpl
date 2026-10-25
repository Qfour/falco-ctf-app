{{/*
The seat (workspace name), checked. EVERY use of the username in this chart goes
through this define (namespace, labels, selector labels, the Ingress host, the
auth-url, the Pod's env), so a render that gets past it has a string seat.

Helm's `--set username=0` reads an integer, `--set username=true` a boolean and
`--set username=null` removes the key (nil): `ctf-<nil>` as a namespace, or a
label written as a bare scalar that Kubernetes refuses (ADR-0042 C4). deploy-user.sh
passes `--set-string`; this check is the chart's own guard for any other caller
(`helm template`, a values file, a different script). An empty string is refused
too: it would render the namespace `ctf-`. A `fail` anywhere aborts the whole render.
*/}}
{{- define "ctf-user.username" -}}
{{- if or (not (kindIs "string" .Values.username)) (eq .Values.username "") -}}
{{- fail (printf "username must be a non-empty string, got %s (%v): pass it with --set-string username=<seat> (ADR-0042 C4)" (kindOf .Values.username) .Values.username) -}}
{{- end -}}
{{- .Values.username -}}
{{- end -}}

{{/*
Render the namespace name (`ctf-<username>`) consistently across templates.
*/}}
{{- define "ctf-user.namespace" -}}
ctf-{{ include "ctf-user.username" . }}
{{- end -}}

{{/*
Common labels for every resource.

P21 item 5 step2 (REFACTORING.md): intentionally NOT migrated onto
falco-ctf-common.labels (charts/falco-ctf-common/templates/_helpers.tpl).
That shared template's fixed output shape is the
name/part-of/managed-by triple used identically by
charts/{scoreboard,auth-policy,collector,docs}; this define's actual
output below carries extra fields (`instance`/`falco-ctf/username`/
`falco-ctf/challenge-id`) in a different relative order
(`instance` before `managed-by`, `part-of` after). Forcing this shape
into the shared template would either reorder its output (a golden-diff
regression) or require the shared template to branch its field order on
which optional args are passed — at which point it stops being one
shared pattern and starts being two patterns wearing one name. See the
shared template's own comment for the same reasoning from the other
side. ctf-user IS a falco-ctf-common consumer for `falco-ctf-common.image`
(see pod.yaml) — just not for labels.
*/}}
{{- define "ctf-user.labels" -}}
app.kubernetes.io/name: ctf-user
app.kubernetes.io/instance: {{ include "ctf-user.username" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: falco-ctf
falco-ctf/username: {{ include "ctf-user.username" . | quote }}
{{- /* P27-1: challengeId is "scenario:<name>" in scenario mode — ':' is not
       a valid k8s label-value character, so sanitize just for this label
       (deploy-user.sh's own `kubectl label namespace` call does the same
       ${CHALLENGE_ID//:/-} substitution; keep both in sync). Every other
       consumer of .Values.challengeId (the challenge container's
       FALCO_CTF_CHALLENGE env, the ctf-flags Secret's hasPrefix "scenario:"
       branch) keeps the raw, un-sanitized value — only this label needs it. */}}
falco-ctf/challenge-id: {{ .Values.challengeId | replace ":" "-" }}
{{- end -}}

{{/*
Selector labels — subset of common labels used in matchLabels (immutable).
*/}}
{{- define "ctf-user.selectorLabels" -}}
app.kubernetes.io/name: ctf-user
app.kubernetes.io/instance: {{ include "ctf-user.username" . | quote }}
{{- end -}}

{{/*
Render the ingress host with `tpl` so users can use `{{ .Values.username }}` etc.
*/}}
{{- define "ctf-user.ingressHost" -}}
{{- /* the host template reads .Values.username directly: check it first */ -}}
{{- $_ := include "ctf-user.username" . -}}
{{ tpl .Values.ingress.host . }}
{{- end -}}
