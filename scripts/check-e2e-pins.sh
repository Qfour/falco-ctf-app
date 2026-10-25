#!/usr/bin/env bash
# check-e2e-pins.sh — kept so ADR-0031 D5 / V9 and the fixtures under scripts/testdata/
# still resolve; the check itself is scripts/check-apk-pins.sh (ADR-0036 D5), which
# absorbed this script and now covers every Dockerfile, not just Dockerfile.e2e.
#
#   scripts/check-e2e-pins.sh [FILE]     FILE defaults to Dockerfile.e2e (this wrapper's
#                                        old scope); same exit codes as check-apk-pins.sh
exec "$(dirname "$0")/check-apk-pins.sh" "${1:-Dockerfile.e2e}"
