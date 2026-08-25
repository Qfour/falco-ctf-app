#!/usr/bin/env bash
# Deploy or upgrade a single CTF user's environment.
#
# Pods are immutable on the volume / container fields — `helm upgrade` cannot
# rotate them in place. This wrapper deletes the workspace Pod when a chart
# upgrade is detected so Helm always reaches the desired state.
#
# Per-challenge values.yaml (postStart) lives in this repo's challenges/; pass
# --challenges-dir to point elsewhere. Briefs/fixtures are image-baked.
#
# Usage:
#   deploy-user.sh [--challenges-dir <path>] [--display-name <name>] \
#                  [--flags-file <path>] [--dns-suffix <suffix>] \
#                  [--frame-ancestors <csp-value>] \
#                  [--egress-lockdown --api-server-cidr <cidr>] \
#                  <username> <challenge-id>
#
# --flags-file <path>: decrypted events flags.yaml ({flags: {id: FALCO{...}}}).
#   Overrides the chart's FALCO{dev-...} defaults with real per-event flags.
#   Omit for local dev (dev placeholders are used).
#
# --frame-ancestors <value>: CSP `frame-ancestors` source list the ttyd-proxy
#   sidecar (P23-3) stamps on every ttyd response. Set this to the portal's
#   OWN origin (P23-4 embeds ttyd in the portal's Terminal tab via iframe),
#   e.g. "https://journey.<dns-suffix>" locally (the participant host serving
#   /portal); prod's real value collapses to a single origin once P19 lands.
#   Omit to keep the chart's fail-safe default ('none' — nobody may frame
#   ttyd), which is correct if the portal is not deployed/reachable yet.
#
# --egress-lockdown: turn on the ctf-user egress NetworkPolicy (P11.5). The
#   workspace can then only reach the collector + kube-dns + the API server;
#   the scoreboard is unreachable directly (webhook-forge防止). Requires
#   --api-server-cidr. Omit for local demo (egress open, non-destructive).
# --api-server-cidr <cidr>: apiserver endpoint CIDR the workspace needs for
#   ttyd's `kubectl exec` (e.g. 10.100.0.1/32 in prod EKS). Only used with
#   --egress-lockdown. Get it from terraform output on the platform side.
#
# Env override:
#   FALCO_CTF_CHALLENGES_DIR=<path>   (lower precedence than --challenges-dir)
#
# Defaults to <repo-root>/challenges (this chart lives at charts/ctf-user).
#
# Display name:
#   `--display-name 'Alice'` records the cosmetic name shown on the
#   scoreboard / /me page for this user. Display names are first-set-only;
#   re-running the script with a different name leaves the original in
#   place (idempotent for re-deploys).
set -euo pipefail

# Chart lives at <app-repo>/charts/ctf-user; challenges/ is a sibling under the
# same repo root. (Moved here from falco-ctf-platform in P2 so the per-user
# deploy no longer depends on a separate app-repo checkout.)
CHART_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${CHART_DIR}/../.." && pwd)"
DEFAULT_CHALLENGES_DIR="${REPO_ROOT}/challenges"

CHALLENGES_DIR=""
DISPLAY_NAME=""
FLAGS_FILE=""
DNS_SUFFIX=""
FRAME_ANCESTORS=""
EGRESS_LOCKDOWN=0
API_SERVER_CIDR=""
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --challenges-dir)
      CHALLENGES_DIR="${2:?--challenges-dir requires a path}"; shift 2 ;;
    --challenges-dir=*)
      CHALLENGES_DIR="${1#--challenges-dir=}"; shift ;;
    --dns-suffix)
      DNS_SUFFIX="${2:?--dns-suffix requires a value}"; shift 2 ;;
    --dns-suffix=*)
      DNS_SUFFIX="${1#--dns-suffix=}"; shift ;;
    --frame-ancestors)
      FRAME_ANCESTORS="${2:?--frame-ancestors requires a value}"; shift 2 ;;
    --frame-ancestors=*)
      FRAME_ANCESTORS="${1#--frame-ancestors=}"; shift ;;
    --display-name)
      DISPLAY_NAME="${2:?--display-name requires a value}"; shift 2 ;;
    --display-name=*)
      DISPLAY_NAME="${1#--display-name=}"; shift ;;
    --flags-file)
      FLAGS_FILE="${2:?--flags-file requires a path}"; shift 2 ;;
    --flags-file=*)
      FLAGS_FILE="${1#--flags-file=}"; shift ;;
    --egress-lockdown)
      EGRESS_LOCKDOWN=1; shift ;;
    --api-server-cidr)
      API_SERVER_CIDR="${2:?--api-server-cidr requires a value}"; shift 2 ;;
    --api-server-cidr=*)
      API_SERVER_CIDR="${1#--api-server-cidr=}"; shift ;;
    -h|--help)
      sed -n '2,45p' "$0"; exit 0 ;;
    --)
      shift; POSITIONAL+=("$@"); break ;;
    -*)
      echo "unknown flag: $1" >&2; exit 2 ;;
    *)
      POSITIONAL+=("$1"); shift ;;
  esac
done
set -- "${POSITIONAL[@]:-}"

USERNAME="${1:?usage: deploy-user.sh [--challenges-dir <path>] [--display-name <name>] <username> <challenge-id>}"
CHALLENGE_ID="${2:?usage: deploy-user.sh [--challenges-dir <path>] [--display-name <name>] <username> <challenge-id>}"

# Egress lockdown (P11.5) requires the apiserver CIDR — without it the chart
# omits the API-server allow and ttyd's `kubectl exec` into the workspace
# breaks. Fail fast here (mirrors platform deploy-event-workspaces.sh), so a
# prod rollout never silently ships a workspace that can't be exec'd into.
if [[ "${EGRESS_LOCKDOWN}" -eq 1 && -z "${API_SERVER_CIDR}" ]]; then
  echo "--egress-lockdown requires --api-server-cidr <cidr>" >&2
  echo "  (the apiserver endpoint CIDR; from terraform output on prod EKS)" >&2
  exit 2
fi

# Precedence: --challenges-dir > $FALCO_CTF_CHALLENGES_DIR > default sibling repo.
CHALLENGES_DIR="${CHALLENGES_DIR:-${FALCO_CTF_CHALLENGES_DIR:-${DEFAULT_CHALLENGES_DIR}}}"
if [[ ! -d "${CHALLENGES_DIR}" ]]; then
  echo "challenges dir not found: ${CHALLENGES_DIR}" >&2
  echo "  (override with --challenges-dir <path> or FALCO_CTF_CHALLENGES_DIR)" >&2
  exit 1
fi
# Resolve to absolute path so helm -f can find the values overlay if cwd changes.
CHALLENGES_DIR="$(cd "${CHALLENGES_DIR}" && pwd)"

# Real per-event flags (from events/<ev>/flags.dec.yaml, shape `{flags: {id: FALCO{...}}}`).
# Each pair becomes --set-string challenge.flags.<id>=<flag>, overriding the
# chart's FALCO{dev-...} defaults. ADR-0001 Option B: these values render into
# the `ctf-flags` Secret and reach only the `plant` initContainer
# (envFrom/secretKeyRef) — the `challenge` container never sees them (I12).
FLAG_ARGS=()
if [[ -n "${FLAGS_FILE}" ]]; then
  [[ -f "${FLAGS_FILE}" ]] || { echo "flags file not found: ${FLAGS_FILE}" >&2; exit 1; }
  while IFS=$'\t' read -r fid fval; do
    [[ -z "${fid}" ]] && continue
    fkey="$(printf '%s' "${fid}" | sed 's/\./\\./g')"
    FLAG_ARGS+=(--set-string "challenge.flags.${fkey}=${fval}")
  done < <(awk '
    /^flags:/ { inblock=1; next }
    inblock && /^[^[:space:]]/ { inblock=0 }
    inblock && /^[[:space:]]+[^[:space:]#]/ {
      line=$0; sub(/^[[:space:]]+/, "", line)
      idx=index(line, ":"); k=substr(line, 1, idx-1); v=substr(line, idx+1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      gsub(/^["'"'"']|["'"'"']$/, "", v)
      printf "%s\t%s\n", k, v
    }' "${FLAGS_FILE}")
  [[ ${#FLAG_ARGS[@]} -gt 0 ]] || { echo "no flags parsed from ${FLAGS_FILE} (expected a top-level 'flags:' map)" >&2; exit 1; }
fi

NS="ctf-${USERNAME}"
RELEASE="${USERNAME}"

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
info()   { printf '\033[36m%s\033[0m\n' "$*"; }

# All-missions mode: challenge-id == "all". Apply the combined plant
# initContainer seed script + mount list from challenges/values-all.yaml
# (ADR-0001 Option B; ran through `plant`, never injected as challenge env —
# see charts/ctf-user/templates/pod.yaml + ctf-flags-secret.yaml). Fixtures/
# briefs are image-baked at /opt/ctf/missions/ (challenge Dockerfile COPY
# challenges/) for every mode — no per-challenge file injection.
ALL_MODE=0
if [[ "${CHALLENGE_ID}" == "all" ]]; then
  ALL_MODE=1
fi

if [[ "${ALL_MODE}" -eq 1 ]]; then
  ALL_VALUES="${CHALLENGES_DIR}/values-all.yaml"
  if [[ ! -f "${ALL_VALUES}" ]]; then
    echo "all-missions mode requires ${ALL_VALUES}" >&2
    exit 1
  fi
  info "using challenges dir: ${CHALLENGES_DIR} (all-missions mode)"
  VALUES_ARGS=(-f "${ALL_VALUES}")
else
  CHALLENGE_DIR="${CHALLENGES_DIR}/${CHALLENGE_ID}"
  CHALLENGE_VALUES="${CHALLENGE_DIR}/values.yaml"

  if [[ ! -d "${CHALLENGE_DIR}" ]]; then
    echo "challenge not found: ${CHALLENGE_DIR}" >&2
    # List challenge sub-directories (each mission is a dir NN-slug); a glob loop
    # avoids parsing `ls` output (SC2010) and copes with odd filenames.
    avail=""
    for d in "${CHALLENGES_DIR}"/*/; do
      [[ -d "${d}" ]] || continue
      avail+="$(basename "${d}") "
    done
    echo "  available: ${avail}all" >&2
    exit 1
  fi

  info "using challenges dir: ${CHALLENGES_DIR}"

  # Optional per-challenge values overlay (e.g. evade challenges' postStart + flag env).
  VALUES_ARGS=()
  if [[ -f "${CHALLENGE_VALUES}" ]]; then
    VALUES_ARGS+=(-f "${CHALLENGE_VALUES}")
  fi
fi

# Determine total step count (5 normally — namespace/rotate/upgrade/verify/
# assert —, 6 when display-name is set).
LAST_STEP=5
if [[ -n "${DISPLAY_NAME}" ]]; then
  LAST_STEP=6
fi

# Namespace ownership (platform#75 / ADR-0011-consistent single-owner pattern).
#
# platform#75: this call used to invoke `helm upgrade --install` without `-n`
# or `--create-namespace`, so the RELEASE metadata was recorded under helm's
# default namespace (usually `default`) while the rendered resources (every
# template in this chart sets `namespace: {{ include "ctf-user.namespace" . }}`
# explicitly) landed in the real `ctf-<user>` namespace. `helm -n ctf-<user>
# list/uninstall` then found nothing (release: not found) — this is what broke
# teardown silently.
#
# The naive fix ("just add -n \"${NS}\" --create-namespace" to the helm call
# below") is NOT safe on its own: this chart used to template its own
# Namespace object (`templates/namespace.yaml`, now removed). `--create-
# namespace` creates a bare, un-annotated Namespace via the k8s API *before*
# the chart's manifest is applied; if the chart's own Namespace template for
# the *same name* were then applied as part of the very same install, Helm's
# ownership-annotation check would see an already-existing object with no
# `meta.helm.sh/release-name` annotation and refuse it ("invalid ownership
# metadata"). That is exactly the two-owners conflict ADR-0011
# (docs/adr/0011-namespace-bootstrap-single-owner.md) fixed for auth-policy/
# collector/scoreboard/docs, and ADR-0011 explicitly requires that any fix to
# this script decide the ctf-user namespace ownership question rather than
# reintroducing the same conflict (see that ADR's Context/Consequences:
# "platform#75 対応時の条件").
#
# ADR-0011's own pattern doesn't fit here as-is: its bootstrap `namespaces`
# chart only `range`s a static list resolved at helmfile render time, but
# ctf-user namespaces are created dynamically per participant outside
# helmfile's management. So this script — the one and only thing that ever
# creates a `ctf-<user>` namespace — takes on the single-owner role directly:
# it creates/labels the Namespace itself with plain `kubectl` (idempotent, no
# Helm involvement) *before* invoking Helm, and the chart no longer templates
# a Namespace object at all. `helm upgrade --install` below then only ever
# sees a namespace that already exists with the right labels, so its
# `--create-namespace` flag is a harmless no-op safety net (it only fires if
# this pre-step were ever skipped by calling helm directly), not the
# mechanism relied on.
#
# Stray releases from before this fix: past `deploy-user.sh` runs (pre-fix)
# recorded their release metadata under the default namespace. If a future
# stand-up finds pending-install/"already exists" errors for a user that
# should be fresh, check `helm -n default list` for a same-named leftover
# release and `helm -n default uninstall <username>` it before re-running
# this script. (Not needed today — prod was fully torn down on 2026-08-17,
# before this fix existed, so no such stray releases are known to exist.)
info "[1/${LAST_STEP}] ensure namespace ${NS} (single owner: this script)"
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "${NS}" --overwrite \
  app.kubernetes.io/name=ctf-user \
  app.kubernetes.io/instance="${USERNAME}" \
  app.kubernetes.io/managed-by=deploy-user.sh \
  app.kubernetes.io/part-of=falco-ctf \
  falco-ctf/username="${USERNAME}" \
  falco-ctf/challenge-id="${CHALLENGE_ID}" \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted >/dev/null

info "[2/${LAST_STEP}] rotate workspace Pod (Pod fields are immutable across helm upgrade)"
# `--ignore-not-found` makes this safe for first-time installs.
# Errors here would only mean the namespace doesn't exist yet, also fine.
kubectl -n "${NS}" delete pod workspace --ignore-not-found --wait=true >/dev/null 2>&1 || true

# Prod image override (chart default is docker.io/falco-ctf/*:dev for local). Set
#   FALCO_CTF_REGISTRY  = <acct>.dkr.ecr.<region>.amazonaws.com/falco-ctf
#   FALCO_CTF_IMAGE_TAG = <git SHA>
# to pull ttyd/ttyd-proxy/challenge from ECR (I5: same SHA tag across all
# images). The challenge repo must keep the `falco-ctf/challenge` substring
# (scoreboard ingest filter).
IMAGE_ARGS=()
if [[ -n "${FALCO_CTF_REGISTRY:-}" ]]; then
  IMAGE_ARGS+=(--set "ttyd.image.repository=${FALCO_CTF_REGISTRY}/ttyd")
  IMAGE_ARGS+=(--set "ttyd.proxy.image.repository=${FALCO_CTF_REGISTRY}/ttyd-proxy")
  IMAGE_ARGS+=(--set "challenge.image.repository=${FALCO_CTF_REGISTRY}/challenge")
fi
if [[ -n "${FALCO_CTF_IMAGE_TAG:-}" ]]; then
  IMAGE_ARGS+=(--set "ttyd.image.tag=${FALCO_CTF_IMAGE_TAG}")
  IMAGE_ARGS+=(--set "ttyd.proxy.image.tag=${FALCO_CTF_IMAGE_TAG}")
  IMAGE_ARGS+=(--set "challenge.image.tag=${FALCO_CTF_IMAGE_TAG}")
fi

# P23-3: CSP frame-ancestors for the ttyd-proxy sidecar. Omit to keep the
# chart's fail-safe default ('none'). Uses --set-string so a bare value like
# 'none' (no quotes) isn't coerced to a YAML boolean/null by helm's --set.
FRAME_ANCESTORS_ARGS=()
if [[ -n "${FRAME_ANCESTORS}" ]]; then
  FRAME_ANCESTORS_ARGS+=(--set-string "ttyd.frameAncestors=${FRAME_ANCESTORS}")
fi

# Egress lockdown (P11.5). Off unless --egress-lockdown is passed, so the local
# demo path (no flag) keeps egress open and non-destructive. When on, enable the
# ctf-user egress NetworkPolicy and pin the apiserver CIDR (validated above).
EGRESS_ARGS=()
if [[ "${EGRESS_LOCKDOWN}" -eq 1 ]]; then
  EGRESS_ARGS+=(--set "networkPolicy.egress.enabled=true")
  EGRESS_ARGS+=(--set "networkPolicy.egress.apiServerCidr=${API_SERVER_CIDR}")
fi

info "[3/${LAST_STEP}] helm upgrade --install ${RELEASE} (challenge=${CHALLENGE_ID})"
# `${arr:+"${arr[@]}"}` lets these expand to nothing when empty under `set -u`.
# `-n "${NS}"` keeps the release metadata in the same namespace as the
# rendered resources (platform#75). `--create-namespace` is a harmless no-op
# here since the "ensure namespace" step above already guarantees ${NS}
# exists before this call — see that step's comment for why relying on
# `--create-namespace` alone (with the chart still templating its own
# Namespace object) would NOT be safe.
helm upgrade --install "${RELEASE}" "${CHART_DIR}" \
  -n "${NS}" --create-namespace \
  --set "username=${USERNAME}" \
  --set "challengeId=${CHALLENGE_ID}" \
  ${DNS_SUFFIX:+--set dnsSuffix="${DNS_SUFFIX}"} \
  ${IMAGE_ARGS:+"${IMAGE_ARGS[@]}"} \
  ${FRAME_ANCESTORS_ARGS:+"${FRAME_ANCESTORS_ARGS[@]}"} \
  ${EGRESS_ARGS:+"${EGRESS_ARGS[@]}"} \
  ${VALUES_ARGS:+"${VALUES_ARGS[@]}"} \
  ${FLAG_ARGS:+"${FLAG_ARGS[@]}"} \
  --wait --timeout 2m

info "[4/${LAST_STEP}] verify"
kubectl -n "${NS}" wait pod/workspace --for=condition=Ready --timeout=60s
HOST=$(kubectl -n "${NS}" get ingress ttyd -o jsonpath='{.spec.rules[0].host}')
green "  ✓ ready — http://${HOST}/"

# ADR-0001 Verification 3 (F2): fail-closed flag-isolation assert, run right
# after the workspace is up. No `if`/`||` wrapper around this call — `set -e`
# above must propagate a non-zero exit from the assert straight out of this
# script (Cross-repo 契約: deploy-user.sh's non-zero exit is a fail-closed
# contract the caller must not swallow; deploy-event-workspaces.sh collects
# per-user exit status on the platform side).
info "[5/${LAST_STEP}] assert flag isolation (ADR-0001 Verification 3)"
"${CHART_DIR}/assert-flag-isolation.sh" "${NS}" "${CHALLENGES_DIR}" "${CHALLENGE_ID}"

# Register the display name on the scoreboard (first-set-only).
# We can't reach scoreboard.scoreboard.svc directly from the operator's
# machine, so we exec into an ingress-nginx pod (which the scoreboard
# NetworkPolicy already admits) and curl from there.
if [[ -n "${DISPLAY_NAME}" ]]; then
  info "[6/${LAST_STEP}] register display name on scoreboard"
  INGRESS_POD=$(kubectl -n ingress-nginx get pod \
    -l app.kubernetes.io/name=ingress-nginx \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -z "${INGRESS_POD}" ]]; then
    yellow "  ⚠ ingress-nginx pod not found; skipping display-name registration"
    yellow "    (run again later with --display-name '${DISPLAY_NAME}' to retry)"
    exit 0
  fi
  PAYLOAD=$(printf '{"name":"%s"}' "${DISPLAY_NAME}")
  RESPONSE=$(kubectl -n ingress-nginx exec "${INGRESS_POD}" -- \
    curl -s -X POST -H 'Content-Type: application/json' \
    -d "${PAYLOAD}" \
    "http://scoreboard.scoreboard.svc/api/users/${USERNAME}/display-name" || true)
  case "${RESPONSE}" in
    *'"ok":true'*)
      green "  ✓ display name registered: ${DISPLAY_NAME}" ;;
    *'already set'*)
      yellow "  ⚠ display name already set; first-set-only semantics keep the original"
      yellow "    ${RESPONSE}" ;;
    *)
      yellow "  ⚠ unexpected response: ${RESPONSE}" ;;
  esac
fi
