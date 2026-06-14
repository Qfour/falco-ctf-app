# Mission 03 (Stealth Read) — plant the flag at the end of /etc/shadow.
# CTF_FLAG_03_STEALTH_READ is injected by the ctf-user chart from the event
# flags secret (the chart supplies a FALCO{dev-...} default for local runs).
echo "# ${CTF_FLAG_03_STEALTH_READ:?flag env not set by ctf-user chart}" >> /etc/shadow
