{{/*
Render the namespace name (`ctf-<username>`) consistently across templates.
*/}}
{{- define "ctf-user.namespace" -}}
ctf-{{ .Values.username }}
{{- end -}}

{{/*
Common labels for every resource.
*/}}
{{- define "ctf-user.labels" -}}
app.kubernetes.io/name: ctf-user
app.kubernetes.io/instance: {{ .Values.username }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: falco-ctf
falco-ctf/username: {{ .Values.username }}
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
app.kubernetes.io/instance: {{ .Values.username }}
{{- end -}}

{{/*
Render the ingress host with `tpl` so users can use `{{ .Values.username }}` etc.
*/}}
{{- define "ctf-user.ingressHost" -}}
{{ tpl .Values.ingress.host . }}
{{- end -}}
