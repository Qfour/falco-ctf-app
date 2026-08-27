{{- /*
  docs.labels / docs.image migrated to falco-ctf-common.labels /
  falco-ctf-common.image (P21 item 5 step2, REFACTORING.md) — see
  charts/falco-ctf-common/templates/_helpers.tpl. Only docs.selectorLabels
  stays chart-local: it is a single-field subset (`app.kubernetes.io/name`
  only) used in immutable matchLabels, a different shape from the
  name/part-of/managed-by triple the shared template covers, and not
  duplicated elsewhere.
*/}}

{{- define "docs.selectorLabels" -}}
app.kubernetes.io/name: docs
{{- end -}}
