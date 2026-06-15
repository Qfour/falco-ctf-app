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
#                  [--flags-file <path>] <username> <challenge-id>
#
# --flags-file <path>: decrypted events flags.yaml ({flags: {id: FALCO{...}}}).
#   Overrides the chart's FALCO{dev-...} defaults with real per-event flags.
#   Omit for local dev (dev placeholders are used).
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
    --display-name)
      DISPLAY_NAME="${2:?--display-name requires a value}"; shift 2 ;;
    --display-name=*)
      DISPLAY_NAME="${1#--display-name=}"; shift ;;
    --flags-file)
      FLAGS_FILE="${2:?--flags-file requires a path}"; shift 2 ;;
    --flags-file=*)
      FLAGS_FILE="${1#--flags-file=}"; shift ;;
    -h|--help)
      sed -n '2,27p' "$0"; exit 0 ;;
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
    echo "  available: $(ls -1 "${CHALLENGES_DIR}" | grep -v '\.\(md\|yaml\|sh\)$' | tr '\n' ' ')all" >&2
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

info "[2/${LAST_STEP}] helm upgrade --install ${RELEASE} (challenge=${CHALLENGE_ID})"
# `${arr:+"${arr[@]}"}` lets these expand to nothing when empty under `set -u`.
helm upgrade --install "${RELEASE}" "${CHART_DIR}" \
  --set "username=${USERNAME}" \
  --set "challengeId=${CHALLENGE_ID}" \
  ${DNS_SUFFIX:+--set dnsSuffix="${DNS_SUFFIX}"} \
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
