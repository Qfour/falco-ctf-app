{{- define "docs.labels" -}}
app.kubernetes.io/name: docs
app.kubernetes.io/part-of: falco-ctf
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "docs.selectorLabels" -}}
app.kubernetes.io/name: docs
{{- end -}}

{{- define "docs.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
