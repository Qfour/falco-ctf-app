#!/usr/bin/env bash
# Build local images and load them into colima's k3s embedded containerd.
# colima k3s shares /run/containerd/containerd.sock with docker — only the
# namespace differs (docker: moby, k3s: k8s.io). We pipe `docker save` into
# `ctr -n k8s.io images import` over ssh.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: build-and-load.sh [--profile <name>] [-h|--help] [IMAGE...]

Build local images and load them into colima's k3s embedded containerd.

Options:
  --profile <name>   Target this colima profile explicitly
                      (colima ssh --profile <name> -- ...). Useful when
                      testing against a disposable profile so it doesn't
                      collide with the default active profile.
                      Default: colima's active profile
                      (colima ssh -- ..., unchanged behavior).
  -h, --help          Show this help and exit.

IMAGE...              Optional positional filter — build only the named
                      images (see the IMAGES array in this script for the
                      valid names). Omit to build all of them.
EOF
}

REGISTRY="${REGISTRY:-falco-ctf}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
COLIMA_PROFILE="${COLIMA_PROFILE:-}"

# name|context|dockerfile  (paths relative to repo root — `-f` is resolved
# from cwd by modern Docker / BuildKit, not from context)
declare -a IMAGES=(
  "ttyd|images/ttyd|images/ttyd/Dockerfile"
  "ttyd-proxy|.|images/ttyd-proxy/Dockerfile"
  "challenge|.|images/challenge/Dockerfile"
  "scoreboard|.|scoreboard/Dockerfile"
  "auth-policy|.|auth-policy/Dockerfile"
  "collector|.|collector/Dockerfile"
  "docs|.|images/docs/Dockerfile"
  "detect-grader|images/detect-grader|images/detect-grader/Dockerfile"
)

# Parse flags. Positional image-name filters are collected into `filter_args`
# and applied after flag parsing, so `--profile` may appear before or after
# them.
filter_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "error: --profile requires a value" >&2
        usage >&2
        exit 1
      fi
      COLIMA_PROFILE="$2"
      shift 2
      ;;
    --profile=*)
      COLIMA_PROFILE="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      filter_args+=("$@")
      break
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      filter_args+=("$1")
      shift
      ;;
  esac
done

# Build the `colima ssh` invocation once. Unspecified --profile keeps the
# existing behavior (targets colima's active profile).
declare -a COLIMA_SSH=(colima ssh)
if [[ -n "${COLIMA_PROFILE}" ]]; then
  COLIMA_SSH+=(--profile "${COLIMA_PROFILE}")
fi
COLIMA_SSH+=(--)

# Optional positional filter — pass image names to build a subset.
if [[ ${#filter_args[@]} -gt 0 ]]; then
  filtered=()
  for want in "${filter_args[@]}"; do
    for spec in "${IMAGES[@]}"; do
      if [[ "${spec%%|*}" == "${want}" ]]; then
        filtered+=("${spec}")
      fi
    done
  done
  IMAGES=("${filtered[@]}")
fi

green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }

for spec in "${IMAGES[@]}"; do
  IFS='|' read -r name ctx dockerfile <<< "${spec}"
  full="${REGISTRY}/${name}:${TAG}"

  info "[build] ${full} (context=${ctx}, dockerfile=${dockerfile})"
  docker build -t "${full}" -f "${dockerfile}" "${ctx}"

  info "[load -> k3s] ${full}"
  ( cd / && docker save "${full}" \
      | "${COLIMA_SSH[@]}" sudo ctr -n k8s.io images import - >/dev/null )
  green "  ✓ ${full} loaded into k3s containerd (k8s.io ns)"
done

info "[verify] images visible to k3s"
( cd / && "${COLIMA_SSH[@]}" sudo ctr -n k8s.io images ls -q ) \
  | grep -E "${REGISTRY}/(ttyd|ttyd-proxy|challenge|scoreboard|auth-policy|collector|docs|detect-grader):" || true
