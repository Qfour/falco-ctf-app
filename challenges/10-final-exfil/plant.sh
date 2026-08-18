# plant-target: /etc/shadow
# plant-seed-source: /opt/ctf/plant-seed/etc/shadow
#
# Mission 10 (Final Exfil) — plant the master key as a CTF_MASTER_KEY line at
# the end of /etc/shadow. Reading it naively fires Read-sensitive (evade with
# Mission 03 /proc/self/root). The capstone then requires exfiltrating it to
# the collector over HTTP (see requireExfil in falco-rule.yaml).
#
# ADR-0001 Option B: same seed-dir model as 03-stealth-read/plant.sh (which
# shares this plant-target — gen-values.sh dedupes the /opt/ctf/plant-seed/
# snapshot copy to run once, then appends both missions' lines in mission-id
# sort order). See that file's header for the full explanation.
#
# CTF_FLAG_10_FINAL_EXFIL is injected into the `plant` initContainer from the
# ctf-flags Secret.
echo "# CTF_MASTER_KEY: ${CTF_FLAG_10_FINAL_EXFIL:?flag env not set by ctf-user chart}" >> "${PLANT_SEED_ROOT}/etc/shadow"
