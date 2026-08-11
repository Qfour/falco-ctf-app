#!/usr/bin/env bash
# Build local images and load them into colima's k3s embedded containerd.
# colima k3s shares /run/containerd/containerd.sock with docker — only the
# namespace differs (docker: moby, k3s: k8s.io). We pipe `docker save` into
# `ctr -n k8s.io images import` over ssh.
set -euo pipefail

cd "$(dirname "$0")/.."

REGISTRY="${REGISTRY:-falco-ctf}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"

# name|context|dockerfile  (paths relative to repo root — `-f` is resolved
# from cwd by modern Docker / BuildKit, not from context)
declare -a IMAGES=(
  "ttyd|images/ttyd|images/ttyd/Dockerfile"
  "challenge|.|images/challenge/Dockerfile"
  "scoreboard|.|scoreboard/Dockerfile"
  "auth-policy|.|auth-policy/Dockerfile"
  "collector|.|collector/Dockerfile"
  "docs|.|images/docs/Dockerfile"
  "detect-grader|images/detect-grader|images/detect-grader/Dockerfile"
)

# Optional positional filter — pass image names to build a subset.
if [[ $# -gt 0 ]]; then
  filtered=()
  for want in "$@"; do
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
      | colima ssh -- sudo ctr -n k8s.io images import - >/dev/null )
  green "  ✓ ${full} loaded into k3s containerd (k8s.io ns)"
done

info "[verify] images visible to k3s"
( cd / && colima ssh -- sudo ctr -n k8s.io images ls -q ) \
  | grep -E "${REGISTRY}/(ttyd|challenge|scoreboard|auth-policy|collector|docs|detect-grader):" || true
