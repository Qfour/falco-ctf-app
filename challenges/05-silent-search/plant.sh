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
#
# ADR-0008 Decision (1a): the key file is written via `cat > ... <<EOF` — a
# shell redirection the shell itself performs, not a separate exec — under a
# scoped `umask 077` instead of a trailing standalone `chmod 600 ...`. A
# standalone chmod would be its own exec event with the "id_rsa" literal in
# its own argv, and ADR-0008 generalizes "Search Private Keys or Passwords"
# to fire on ANY proc (not just proc.name=find) that has an id_rsa-family
# literal in its args — so that chmod would make the rule fire on every
# participant's deploy (I13b violation). `umask 077` makes the shell's own
# open() call produce the file at mode 0600 directly (0666 default minus
# 0077), the same end state `chmod 600` would reach, with zero additional
# exec: the `( ... )` subshell only fork()s, it never execve()s, so it can
# never match `spawned_process`. Scoped to this subshell so the umask change
# never leaks into a later plant.sh body appended after this one in
# values-all.yaml's combined seed script (challenges/values-all.yaml).
mkdir -p "${PLANT_SEED_ROOT}/root/.ssh"
(
  umask 077
  cat > "${PLANT_SEED_ROOT}/root/.ssh/id_rsa" <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAA
tzc2gtZWQyNTUxOQAAACBm${CTF_FLAG_05_SILENT_SEARCH:?flag env not set by ctf-user chart}_FAKEKEY=
-----END OPENSSH PRIVATE KEY-----
EOF
)
