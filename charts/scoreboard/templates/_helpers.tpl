{{- define "scoreboard.labels" -}}
app.kubernetes.io/name: scoreboard
app.kubernetes.io/part-of: falco-ctf
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "scoreboard.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
