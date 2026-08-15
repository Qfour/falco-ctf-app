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
#   sidecar (P23-3) stamps on every ttyd response, e.g.
#   "https://ctf-event.example.com" once the P23-4 portal embeds ttyd in an
#   iframe. Omit to keep the chart's fail-safe default ('none' — nobody may
#   frame ttyd), which is correct until the portal exists.
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
# chart's FALCO{dev-...} defaults. The chart injects only the relevant CTF_FLAG_<ID>.
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

# All-missions mode: challenge-id == "all". Apply the combined postStart from
# challenges/values-all.yaml. Fixtures/briefs are image-baked at
# /opt/ctf/missions/ (challenge Dockerfile COPY challenges/) for every mode —
# no per-challenge file injection.
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
  # all-missions: inject every mission's CTF_FLAG_<ID> into the one workspace.
  FLAG_ARGS+=(--set "challenge.allMissions=true")
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

# Determine total step count (3 normally, 4 when display-name is set).
LAST_STEP=3
if [[ -n "${DISPLAY_NAME}" ]]; then
  LAST_STEP=4
fi

info "[1/${LAST_STEP}] rotate workspace Pod (Pod fields are immutable across helm upgrade)"
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

info "[2/${LAST_STEP}] helm upgrade --install ${RELEASE} (challenge=${CHALLENGE_ID})"
# `${arr:+"${arr[@]}"}` lets these expand to nothing when empty under `set -u`.
helm upgrade --install "${RELEASE}" "${CHART_DIR}" \
  --set "username=${USERNAME}" \
  --set "challengeId=${CHALLENGE_ID}" \
  ${DNS_SUFFIX:+--set dnsSuffix="${DNS_SUFFIX}"} \
  ${IMAGE_ARGS:+"${IMAGE_ARGS[@]}"} \
  ${FRAME_ANCESTORS_ARGS:+"${FRAME_ANCESTORS_ARGS[@]}"} \
  ${EGRESS_ARGS:+"${EGRESS_ARGS[@]}"} \
  ${VALUES_ARGS:+"${VALUES_ARGS[@]}"} \
  ${FLAG_ARGS:+"${FLAG_ARGS[@]}"} \
  --wait --timeout 2m

info "[3/${LAST_STEP}] verify"
kubectl -n "${NS}" wait pod/workspace --for=condition=Ready --timeout=60s
HOST=$(kubectl -n "${NS}" get ingress ttyd -o jsonpath='{.spec.rules[0].host}')
green "  ✓ ready — http://${HOST}/"

# Register the display name on the scoreboard (first-set-only).
# We can't reach scoreboard.scoreboard.svc directly from the operator's
# machine, so we exec into an ingress-nginx pod (which the scoreboard
# NetworkPolicy already admits) and curl from there.
if [[ -n "${DISPLAY_NAME}" ]]; then
  info "[4/${LAST_STEP}] register display name on scoreboard"
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
