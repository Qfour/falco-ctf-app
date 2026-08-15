#!/bin/sh
set -eu

# Pod name — k8s sets HOSTNAME to the pod name by default.
# shellcheck disable=SC3028  # HOSTNAME is a k8s-injected env var, not the shell builtin.
POD="${HOSTNAME:?HOSTNAME not set}"
CONTAINER="${TTYD_TARGET_CONTAINER:-challenge}"
PORT="${TTYD_PORT:-7681}"
# P23-3: TTYD_INTERFACE lets the ctf-user chart opt in to loopback-only
# binding once ttyd sits behind the ttyd-proxy sidecar (CSP frame-ancestors
# clickjacking mitigation). Image default stays 0.0.0.0 for backward compat
# with any caller that doesn't set it; the chart explicitly sets
# TTYD_INTERFACE=127.0.0.1 to adopt the new topology.
IFACE="${TTYD_INTERFACE:-0.0.0.0}"

# kubectl auto-detects in-cluster config from /var/run/secrets/kubernetes.io/serviceaccount/.
# The SA mounted there must have `pods/exec` on this Pod (granted by the chart).
exec ttyd \
  --port "${PORT}" \
  --interface "${IFACE}" \
  --writable \
  -t titleFixed="falco-ctf: ${POD}" \
  -- kubectl exec -i -t -c "${CONTAINER}" "${POD}" -- /bin/bash -l
