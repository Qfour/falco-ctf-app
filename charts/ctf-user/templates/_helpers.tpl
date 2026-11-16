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
ADR-0056 D11 (A5b): everything the chart refuses about the evidence bundles. Called by
templates/ctf-evidence-secret.yaml and by templates/pod.yaml (which writes the file
names into the `plant` initContainer's sh script, so it does not rely on the other
template having run); a `fail` anywhere aborts the whole render. Renders nothing.

  - plant.mounts: an entry that has `evidence` has it as the boolean true, a challenge
    id (the one grammar, challengeid.Pattern) in `challenge` (once per challenge), and a
    path of plain elements (the value is written into the sh script).
  - the challenges of those entries == the keys of .Values.evidence.challenges. Both
    ways: a mount with no bundle would plant an empty directory, a bundle with no mount
    would be a Secret nothing copies. With no evidence mount and no key (every
    deployment before an investigate challenge exists) the sets are equal and nothing
    below applies.
  - per challenge, B2's rules (ADR-0056, the validator enforces the same): `files` only,
    1..64 files, names ^[a-z0-9][a-z0-9._-]{0,62}$ (so never `..`, a slash, a space, a
    glob or a `$`), string values, at most 512 KiB (524288 bytes) in all. Over all
    challenges at most 2 MiB (2097152 bytes): the copies are written into the
    plant-seed emptyDir (sizeLimit 4Mi in pod.yaml), and a Pod over the limit is
    evicted at run time, so the render refuses it first.
  - with evidence: plant.seedScript is the [sh, -c, <script>] gen-values.sh generates
    (the copy lines are appended to that one script, so it must be that shape).
Only ids, names and counts go into a message, never a value.
*/}}
{{- define "ctf-user.evidence.check" -}}
{{- $mounted := list -}}
{{- range $m := .Values.plant.mounts -}}
{{- if hasKey $m "evidence" -}}
{{- if not (and (kindIs "bool" $m.evidence) $m.evidence) -}}
{{- fail (printf "ADR-0056 D11: plant.mounts entry %v has an `evidence` key that is not the boolean true" $m.path) -}}
{{- end -}}
{{- if not (kindIs "string" $m.challenge) -}}
{{- fail (printf "ADR-0056 D11: plant.mounts entry %v is `evidence: true` but has no string `challenge`" $m.path) -}}
{{- end -}}
{{- if not (regexMatch "^[0-9]{2}-[a-z0-9-]{1,60}$" $m.challenge) -}}
{{- fail (printf "ADR-0056 D11: plant.mounts entry %v: challenge %q is not a challenge id (^[0-9]{2}-[a-z0-9-]{1,60}$)" $m.path $m.challenge) -}}
{{- end -}}
{{- if has $m.challenge $mounted -}}
{{- fail (printf "ADR-0056 D11: plant.mounts has more than one evidence entry for challenge %q" $m.challenge) -}}
{{- end -}}
{{- if not (kindIs "string" $m.path) -}}
{{- fail (printf "ADR-0056 D11: plant.mounts entry of challenge %q has no string path" $m.challenge) -}}
{{- end -}}
{{- if or (not (regexMatch "^(/[A-Za-z0-9._-]+)+$" $m.path)) (regexMatch `(^|/)\.\.?(/|$)` $m.path) -}}
{{- fail (printf "ADR-0056 D11: plant.mounts evidence path %q of challenge %q is not an absolute path of [A-Za-z0-9._-] elements without . or .. (it is written into the plant initContainer's sh script)" $m.path $m.challenge) -}}
{{- end -}}
{{- $mounted = append $mounted $m.challenge -}}
{{- end -}}
{{- end -}}
{{- $ev := .Values.evidence.challenges -}}
{{- if not (kindIs "map" $ev) -}}
{{- fail "ADR-0056 D11: .Values.evidence.challenges must be a map of challenge id to {files: {<name>: <content>}}" -}}
{{- end -}}
{{- $have := keys $ev | sortAlpha -}}
{{- $want := sortAlpha $mounted -}}
{{- if ne (join "," $have) (join "," $want) -}}
{{- fail (printf "ADR-0056 D11: the challenges of plant.mounts[evidence: true] [%s] and the keys of evidence.challenges [%s] are not the same set" (join "," $want) (join "," $have)) -}}
{{- end -}}
{{- $grand := 0 -}}
{{- range $cid, $c := $ev -}}
{{- if not (regexMatch "^[0-9]{2}-[a-z0-9-]{1,60}$" $cid) -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges key %q is not a challenge id (^[0-9]{2}-[a-z0-9-]{1,60}$)" $cid) -}}
{{- end -}}
{{- if not (kindIs "map" $c) -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s must be a map with the single key `files`" $cid) -}}
{{- end -}}
{{- if ne (join "," (keys $c)) "files" -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s must have the single key `files` (got [%s])" $cid (join "," (keys $c | sortAlpha))) -}}
{{- end -}}
{{- if not (kindIs "map" $c.files) -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s.files must be a map of file name to content" $cid) -}}
{{- end -}}
{{- $n := len $c.files -}}
{{- if or (lt $n 1) (gt $n 64) -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s.files has %d files (want 1..64)" $cid $n) -}}
{{- end -}}
{{- $total := 0 -}}
{{- range $name, $v := $c.files -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9._-]{0,62}$" $name) -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s.files has the file name %q (want ^[a-z0-9][a-z0-9._-]{0,62}$)" $cid $name) -}}
{{- end -}}
{{- if not (kindIs "string" $v) -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s.files.%s is not a string (pass it with --set-string or as a quoted YAML string)" $cid $name) -}}
{{- end -}}
{{- $total = add $total (len $v) -}}
{{- end -}}
{{- if gt $total 524288 -}}
{{- fail (printf "ADR-0056 D11: evidence.challenges.%s.files is %d bytes in all (want at most 524288 = 512 KiB)" $cid $total) -}}
{{- end -}}
{{- $grand = add $grand $total -}}
{{- end -}}
{{- if gt $grand 2097152 -}}
{{- fail (printf "ADR-0056 D11: the evidence of all challenges is %d bytes in all (want at most 2097152 = 2 MiB: half of the plant-seed emptyDir's sizeLimit 4Mi, which the copies are written into; if more is needed, review the sizeLimit in templates/pod.yaml together with this limit)" $grand) -}}
{{- end -}}
{{- if $have -}}
{{- $s := .Values.plant.seedScript -}}
{{- if not (kindIs "slice" $s) -}}
{{- fail "ADR-0056 D11: with evidence, plant.seedScript must be a list [sh, -c, <script>] as gen-values.sh generates it" -}}
{{- end -}}
{{- if ne (len $s) 3 -}}
{{- fail (printf "ADR-0056 D11: with evidence, plant.seedScript must have 3 elements [sh, -c, <script>] as gen-values.sh generates it (got %d)" (len $s)) -}}
{{- end -}}
{{- if or (ne (index $s 0) "sh") (ne (index $s 1) "-c") (not (kindIs "string" (index $s 2))) -}}
{{- fail "ADR-0056 D11: with evidence, plant.seedScript elements must be sh, -c and a string script as gen-values.sh generates it" -}}
{{- end -}}
{{- if not (hasPrefix "set -eu\n" (index $s 2)) -}}
{{- fail "ADR-0056 D11: with evidence, the plant.seedScript script must start with `set -eu` as gen-values.sh generates it" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The copy lines of the evidence bundles, appended to the plant script by pod.yaml
(ADR-0056 D11). Their SHAPE is defined once, by render_evidence_copy in
challenges/gen-values.sh; scripts/check-flag-isolation.sh holds this output to that
function's. Challenges in byte order of their id, files in byte order of their name
(sortAlpha sorts bytes), each file by name: cp, then chmod 0444. The output starts with
a newline (it follows the script's last line) and does not end with one.
*/}}
{{- define "ctf-user.evidence.copyLines" -}}
{{- $mountOf := dict -}}
{{- range $m := .Values.plant.mounts -}}
{{- if hasKey $m "evidence" -}}
{{- $_ := set $mountOf $m.challenge $m.path -}}
{{- end -}}
{{- end -}}
{{- range $cid := (keys .Values.evidence.challenges | sortAlpha) -}}
{{- $path := get $mountOf $cid -}}
{{- range $name := (keys (get (get $.Values.evidence.challenges $cid) "files") | sortAlpha) }}
cp "/opt/ctf/evidence-src/{{ $cid }}/{{ $name }}" "${PLANT_SEED_ROOT}{{ $path }}/{{ $name }}"
chmod 0444 "${PLANT_SEED_ROOT}{{ $path }}/{{ $name }}"
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render the ingress host with `tpl` so users can use `{{ .Values.username }}` etc.
*/}}
{{- define "ctf-user.ingressHost" -}}
{{- /* the host template reads .Values.username directly: check it first */ -}}
{{- $_ := include "ctf-user.username" . -}}
{{ tpl .Values.ingress.host . }}
{{- end -}}
