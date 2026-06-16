# Mission 10 (Final Exfil) — plant the master key as a CTF_MASTER_KEY line at
# the end of /etc/shadow. Reading it naively fires Read-sensitive (evade with
# Mission 03 /proc/self/root). The capstone then requires exfiltrating it to the
# collector over HTTP (see requireExfil in falco-rule.yaml).
# CTF_FLAG_10_FINAL_EXFIL is injected by the ctf-user chart.
echo "# CTF_MASTER_KEY: ${CTF_FLAG_10_FINAL_EXFIL:?flag env not set by ctf-user chart}" >> /etc/shadow
