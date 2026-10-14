#!/usr/bin/env bash
# check-e2e-pins.sh — fail when an apk pin in Dockerfile.e2e is no longer in
# Alpine's index (ADR-0031 D5). Alpine keeps ONE version of each package, so the
# day Chromium is updated the exact pin disappears and `make e2e` stops building;
# this finds it from a daily job (.github/workflows/e2e-pins.yaml) instead of
# from the next PR. Needs Docker and network.
#
#   scripts/check-e2e-pins.sh [FILE]     FILE defaults to Dockerfile.e2e
#
# It runs `apk policy` inside the very base image FILE builds from (the golang
# image, by digest), for every `name=version` of FILE's `apk add` RUN (`\`
# continuation lines included), and fails
# when the pinned version is not among the versions the index lists.
# Exit: 0 all pins current, 1 a pin is gone/stale or FILE has no pin to check,
# 2 Docker or network trouble (not a verdict about the pins).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

file="${1:-Dockerfile.e2e}"
[ -f "$file" ] || { echo "check-e2e-pins: $file not found" >&2; exit 1; }

image="$(grep -m1 -E '^FROM [^ ]+' "$file" | awk '{print $2}')"
case "$image" in
  golang:*@sha256:*) ;;
  *) echo "check-e2e-pins: first FROM of $file is '$image', want a digest-pinned golang image" >&2; exit 1 ;;
esac

# Join `\`-continued lines first: a pin on a continuation line of the `apk add`
# RUN would otherwise never be read, and so never be checked.
pins="$(awk '{ if (sub(/\\$/, "")) { buf = buf $0 " "; next } print buf $0; buf = "" } END { if (buf != "") print buf }' "$file" \
  | grep -E '^RUN apk add' | tr -s ' \t' '\n\n' | grep -E '^[a-z0-9][a-z0-9._+-]*=[0-9][^ ]*$')"
if [ -z "$pins" ]; then
  echo "check-e2e-pins: no name=version pin on an 'apk add' line of $file" >&2
  exit 1
fi

names="$(printf '%s\n' "$pins" | cut -d= -f1 | tr '\n' ' ')"
# shellcheck disable=SC2086  # $names is a space-separated list of package names
if ! policy="$(docker run --rm "$image" sh -c "apk update >/dev/null && apk policy $names" 2>&1)"; then
  echo "check-e2e-pins: could not query the index:" >&2
  echo "$policy" >&2
  exit 2
fi

status=0
while IFS='=' read -r name version; do
  # `apk policy` prints "  <version>:" under "<name> policy:" for every version in the index.
  listed="$(printf '%s\n' "$policy" | awk -v n="$name" '
    $0 == n " policy:" { in_pkg = 1; next }
    /^[^ ]/ { in_pkg = 0 }
    in_pkg && /^  [^ ].*:$/ { sub(/^  /, ""); sub(/:$/, ""); print }')"
  if printf '%s\n' "$listed" | grep -Fxq "$version"; then
    echo "ok:   $name=$version is in the index"
  else
    echo "FAIL: $name=$version is not in the index (index has: ${listed:-nothing}) — bump the pin in $file (see its header)"
    status=1
  fi
done <<<"$pins"
exit "$status"
