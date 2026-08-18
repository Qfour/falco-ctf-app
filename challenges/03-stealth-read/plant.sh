# plant-target: /etc/shadow
# plant-seed-source: /opt/ctf/plant-seed/etc/shadow
#
# Mission 03 (Stealth Read) — plant the flag at the end of /etc/shadow.
#
# ADR-0001 Option B: this script runs in the `plant` initContainer, never in
# the challenge container. It never touches the real /etc/shadow — it writes
# into the seed emptyDir at $PLANT_SEED_ROOT (gen-values.sh sets this var and,
# because `plant-seed-source` above is declared, copies the build-time
# snapshot from /opt/ctf/plant-seed/etc/shadow into
# $PLANT_SEED_ROOT/etc/shadow *before* this line runs). The chart then binds
# $PLANT_SEED_ROOT/etc/shadow onto /etc/shadow in the challenge container via
# a subPath mount (read-only) — the participant sees the same path they
# always did.
#
# CTF_FLAG_03_STEALTH_READ is injected into the `plant` initContainer from the
# ctf-flags Secret (the chart supplies a FALCO{dev-...} default for local
# runs).
echo "# ${CTF_FLAG_03_STEALTH_READ:?flag env not set by ctf-user chart}" >> "${PLANT_SEED_ROOT}/etc/shadow"
