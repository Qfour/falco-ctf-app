# plant-target: /root/.ssh
# plant-target-type: dir
#
# Mission 05 (Silent Search) — embed the flag inside a fake OpenSSH private
# key so the player must read it without putting "id_rsa" on the command
# line.
#
# ADR-0001 Option B + ADR-0007 Option 1: this script runs in the `plant`
# initContainer and writes into the seed emptyDir at
# $PLANT_SEED_ROOT/root/.ssh (not the real /root/.ssh — the challenge image
# doesn't even have that directory). No `plant-seed-source` header is
# declared because this plant-target has no build-time base data to restore
# first (unlike /etc/shadow) — 05 creates the whole file itself.
# `plant-target-type: dir` means the mount IS the plant-target itself (no
# enclosing-directory indirection needed — this was already directory
# granularity before ADR-0007, and stays readOnly:true since no mission
# needs to write into /root/.ssh). The chart binds $PLANT_SEED_ROOT/root/.ssh
# onto /root/.ssh in the challenge container via a subPath mount.
#
# CTF_FLAG_05_SILENT_SEARCH is injected into the `plant` initContainer from
# the ctf-flags Secret.
mkdir -p "${PLANT_SEED_ROOT}/root/.ssh"
cat > "${PLANT_SEED_ROOT}/root/.ssh/id_rsa" <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAA
tzc2gtZWQyNTUxOQAAACBm${CTF_FLAG_05_SILENT_SEARCH:?flag env not set by ctf-user chart}_FAKEKEY=
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 "${PLANT_SEED_ROOT}/root/.ssh/id_rsa"
