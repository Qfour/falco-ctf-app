#!/bin/sh
set -eu

# Pod name — k8s sets HOSTNAME to the pod name by default.
# shellcheck disable=SC3028  # HOSTNAME is a k8s-injected env var, not the shell builtin.
POD="${HOSTNAME:?HOSTNAME not set}"
CONTAINER="${TTYD_TARGET_CONTAINER:-challenge}"
PORT="${TTYD_PORT:-7681}"

# kubectl auto-detects in-cluster config from /var/run/secrets/kubernetes.io/serviceaccount/.
# The SA mounted there must have `pods/exec` on this Pod (granted by the chart).
exec ttyd \
  --port "${PORT}" \
  --interface 0.0.0.0 \
  --writable \
  -t titleFixed="falco-ctf: ${POD}" \
  -- kubectl exec -i -t -c "${CONTAINER}" "${POD}" -- /bin/bash -l
