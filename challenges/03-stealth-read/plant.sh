# plant-target: /etc/shadow
# plant-target-type: file
# plant-seed-source: /opt/ctf/plant-seed/etc
# plant-mount-readonly: false
#
# Mission 03 (Stealth Read) — plant the flag at the end of /etc/shadow.
#
# ADR-0001 Option B + ADR-0007 Option 1: this script runs in the `plant`
# initContainer, never in the challenge container. It never touches the real
# /etc/shadow — it writes into the seed emptyDir at $PLANT_SEED_ROOT
# (gen-values.sh sets this var and, because `plant-seed-source` above is
# declared, restores the WHOLE /etc directory — not just this one file —
# from the build-time snapshot at /opt/ctf/plant-seed/etc/ into
# $PLANT_SEED_ROOT/etc/ *before* this line runs; gen-values.sh dedupes this
# restore so it happens once even though 10-final-exfil shares this
# plant-target). The chart then binds $PLANT_SEED_ROOT/etc onto /etc in the
# challenge container via a **directory-granularity** subPath mount (ADR-0007
# — a file-granularity mount of /etc/shadow itself made the container
# runtime's own mount-setup trigger `Read sensitive file untrusted` on every
# deploy, because `open_read`-family rules match any `fd.typechar='f'` open
# of the destination; a directory destination can never satisfy that) — the
# participant still sees the exact same /etc/shadow path they always did.
#
# `plant-mount-readonly: false`: this mount is NOT readOnly, because mission
# 09 (challenges/09-hidden-cache, which has no plant.sh of its own — its
# plant-target /etc/sudoers is baked directly into the image, not planted)
# needs `ln /etc/sudoers /etc/.cache.bak` to succeed, which requires a
# writable /etc. This has nothing to do with 03/10's own plant.sh logic; it
# is recorded here (the first mission, in sort order, to declare the /etc
# mount) purely because gen-values.sh needs exactly one place to read it
# from and 09 has no plant.sh to host the declaration. See
# docs/adr/0007-plant-mount-directory-granularity.md Consequences
# ("諦めたもの" — readOnly:true is given up for this mount only;
# mission 05's /root/.ssh mount stays readOnly:true).
#
# CTF_FLAG_03_STEALTH_READ is injected into the `plant` initContainer from the
# ctf-flags Secret (the chart supplies a FALCO{dev-...} default for local
# runs).
echo "# ${CTF_FLAG_03_STEALTH_READ:?flag env not set by ctf-user chart}" >> "${PLANT_SEED_ROOT}/etc/shadow"
