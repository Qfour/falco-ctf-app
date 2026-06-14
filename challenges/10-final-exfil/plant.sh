# Mission 10 (Final Exfil) — plant the final flag as a NIMBUS_FINAL line at the
# end of /etc/shadow. CTF_FLAG_10_FINAL_EXFIL is injected by the ctf-user chart.
echo "# NIMBUS_FINAL: ${CTF_FLAG_10_FINAL_EXFIL:?flag env not set by ctf-user chart}" >> /etc/shadow
