{{- define "collector.labels" -}}
app.kubernetes.io/name: collector
app.kubernetes.io/part-of: falco-ctf
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "collector.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
