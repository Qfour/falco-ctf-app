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
falco-ctf/challenge-id: {{ .Values.challengeId }}
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
