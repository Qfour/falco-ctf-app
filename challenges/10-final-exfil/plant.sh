# plant-target: /etc/shadow
# plant-target-type: file
# plant-seed-source: /opt/ctf/plant-seed/etc
#
# Mission 10 (Final Exfil) — plant the master key as a CTF_MASTER_KEY line at
# the end of /etc/shadow. Reading it naively fires Read-sensitive (evade with
# Mission 03 /proc/self/root). The capstone then requires exfiltrating it to
# the collector over HTTP (see requireExfil in falco-rule.yaml).
#
# ADR-0001 Option B + ADR-0007 Option 1: same seed-dir model as
# 03-stealth-read/plant.sh (which shares this plant-target — gen-values.sh
# dedupes the /opt/ctf/plant-seed/etc/ directory-wide restore to run once,
# then appends both missions' lines in mission-id sort order). See that
# file's header for the full explanation, including why the mount is
# directory-granularity (/etc, not /etc/shadow) and why it is NOT readOnly
# (mission 09's hardlink target).
#
# CTF_FLAG_10_FINAL_EXFIL is injected into the `plant` initContainer from the
# ctf-flags Secret.
echo "# CTF_MASTER_KEY: ${CTF_FLAG_10_FINAL_EXFIL:?flag env not set by ctf-user chart}" >> "${PLANT_SEED_ROOT}/etc/shadow"
