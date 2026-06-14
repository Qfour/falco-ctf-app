{{- define "auth-policy.labels" -}}
app.kubernetes.io/name: auth-policy
app.kubernetes.io/part-of: falco-ctf
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "auth-policy.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
