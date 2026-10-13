{{- /*
  falco-ctf-common — shared named templates (P21 item 5, REFACTORING.md).

  step1 (landed): the two patterns that were byte-identical across
  charts/{scoreboard,auth-policy,collector} — Pod/container securityContext
  (Invariant I2: runAsUser 65532) and the default-deny NetworkPolicy.

  step2 (this addition): `labels` and `image`.
  - `falco-ctf-common.labels` is used by charts/{scoreboard,auth-policy,
    collector,docs} — all four had a byte-identical
    name/part-of/managed-by triple. charts/ctf-user's own `ctf-user.labels`
    carries additional fields (`instance`/`username`/
    `falco-ctf/challenge-id`) in a different field order and stays
    chart-local (see the define's own comment for why forcing it into this
    template would risk a golden-diff regression rather than avoid one).
  - `falco-ctf-common.image` is used by all five charts, including
    ctf-user's three `challenge.image` call sites (plant/missions-scope/
    challenge containers) and the ttyd/ttyd.proxy call sites — the
    `<repository>:<tag>` assembly is identical everywhere.
  kube-dns egress is still out of scope (no such pattern was found
  duplicated at step2 time; left for a future step if one appears).

  docs/ctf-user remain non-callers of the step1 templates (securityContext/
  NetworkPolicy) — ctf-user's `challenge` container is intentionally root
  (I2 does not apply) and docs/ttyd/ttyd-proxy use different UIDs; see
  .claude/rules/falco-ctf-app-conventions.md "UID 一覧". They ARE new
  callers of the step2 templates below (labels for docs; image for both).

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

{{- /*
  falco-ctf-common.labels — the `app.kubernetes.io/{name,part-of,managed-by}`
  triple shared byte-identically by charts/{scoreboard,auth-policy,collector,
  docs} today (P21 item 5, step2).

  charts/ctf-user's `ctf-user.labels` is NOT a caller of this template. Its
  actual output is:
    app.kubernetes.io/name: ctf-user
    app.kubernetes.io/instance: <username>
    app.kubernetes.io/managed-by: <Release.Service>
    app.kubernetes.io/part-of: falco-ctf
    falco-ctf/username: <username>
    falco-ctf/challenge-id: <sanitized challengeId>
  — both an extra field set AND a different relative order of
  `managed-by`/`part-of` than this template's fixed
  name/part-of/managed-by shape. There is no argument shape that produces
  both orderings from one define without conditionals whose branch depends
  on which fields the caller passes — at that point it stops being "one
  shared pattern with parameters" and starts being two patterns wearing one
  name, which is the exact trap the file-level comment above warns about
  ("無理に一つのテンプレートに押し込めて実際の値を変えてしまわないこと",
  REFACTORING.md P21 item 5 step2 task notes). Left chart-local by design.

  Arg: a dict with `name` (chart/app name, e.g. "scoreboard") and
  `managedBy` (pass `.Release.Service` explicitly from the call site — this
  template does not read `.Release` itself, same "explicit argument"
  discipline as every other define in this file). `part-of` is hardcoded to
  the literal "falco-ctf" because all four current callers already hardcode
  that exact constant themselves.

  Usage:
    labels:
      {{- include "falco-ctf-common.labels" (dict "name" "scoreboard" "managedBy" .Release.Service) | nindent 4 }}
*/}}
{{- define "falco-ctf-common.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/part-of: falco-ctf
app.kubernetes.io/managed-by: {{ .managedBy }}
{{- end -}}

{{- /*
  falco-ctf-common.image — the `<repository>:<tag>` string assembly
  duplicated across all five charts' image references: charts/{scoreboard,
  auth-policy,collector,docs} each have exactly one call site;
  charts/ctf-user has five (three for `challenge.image` — the plant,
  missions-scope, and challenge containers all run the same image, I5 — plus
  one each for `ttyd.image` and `ttyd.proxy.image`).

  Arg: a dict with `repository` and `tag`. Optional `appVersion` —
  scoreboard/auth-policy/collector/docs use `.Values.image.tag | default
  .Chart.AppVersion` today, so they pass it; ctf-user's five call sites
  always carry an explicit tag (deploy-user.sh / the generated
  challenges/values-*.yaml never leave `.tag` empty) and omit `appVersion`
  entirely — the dict simply has no such key, `default` never has a reason
  to fall through to it, and the rendered output is unchanged either way.

  Usage:
    image: {{ include "falco-ctf-common.image" (dict "repository" .Values.image.repository "tag" .Values.image.tag "appVersion" .Chart.AppVersion) | quote }}
    image: {{ include "falco-ctf-common.image" (dict "repository" .Values.challenge.image.repository "tag" .Values.challenge.image.tag) | quote }}
*/}}
{{- define "falco-ctf-common.image" -}}
{{- $tag := .tag | default .appVersion -}}
{{ .repository }}:{{ $tag }}
{{- end -}}

{{- /*
  falco-ctf-common.ingressPassthrough — the free-form Ingress annotation
  passthrough (scoreboard ingress.annotations / ingress.journeyAnnotations,
  docs ingress.annotations), as an ALLOWLIST (ADR-0034 D4 / V12).

  It was a denylist of the nginx.ingress.kubernetes.io/auth- prefix. A denylist
  cannot name every key that defeats the identity-stamping auth gate:
  `satisfy: "any"` plus a `whitelist-source-range` / `allowlist-source-range`
  lets a request from an allowed address skip the auth subrequest entirely, so
  no canonical X-Auth-Request-* headers are stamped and the internal-only 403s
  stop distinguishing the browser path. So the passthrough accepts only the keys
  the platform helmfile actually supplies today, and every other key fails the
  render. A new key is added HERE, in the same PR that has a reason for it, with
  a V12 case (internal/apispec/ingressparity/authurl_test.go).

  Allowed:
    nginx.ingress.kubernetes.io/ssl-redirect     (prod, vm-prod)
    nginx.ingress.kubernetes.io/proxy-body-size  (prod, vm-prod)
    cert-manager.io/cluster-issuer               (vm-prod admin Ingress)

  Arg: a dict with `field` (the values path, for the error message) and
  `annotations` (the map). Emits the map as YAML; the caller indents it.

  Usage:
    {{- with .Values.ingress.annotations }}
    {{- include "falco-ctf-common.ingressPassthrough" (dict "field" "ingress.annotations" "annotations" .) | nindent 4 }}
    {{- end }}
*/}}
{{- define "falco-ctf-common.ingressPassthrough" -}}
{{- $allowed := list "nginx.ingress.kubernetes.io/ssl-redirect" "nginx.ingress.kubernetes.io/proxy-body-size" "cert-manager.io/cluster-issuer" -}}
{{- range $k, $_ := .annotations -}}
{{- if not (has (toString $k) $allowed) -}}
{{- fail (printf "%s must not set %s (the passthrough is an allowlist: %s; the auth gate and everything that can bypass it, e.g. satisfy / *-source-range / auth-*, is fixed by this chart)" $.field $k (join ", " $allowed)) -}}
{{- end -}}
{{- end -}}
{{- toYaml .annotations -}}
{{- end -}}
