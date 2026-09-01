# plant-target: /opt/nimbus/vault
# plant-target-type: dir
#
# Mission 03 (Stealth Read) — plant the flag alone in a dedicated vault file,
# NOT appended to /etc/shadow (ADR-0025-derived design, 2026-09-01 CEO
# decision: separate evade flags out of the shared /etc/shadow file into a
# purpose-built vault so 03/10 no longer visibly "converge on the same
# answer file").
#
# ADR-0001 Option B + ADR-0007 Option 1: this script runs in the `plant`
# initContainer, never in the challenge container. $PLANT_SEED_ROOT is the
# seed emptyDir (gen-values.sh sets this var). `plant-target-type: dir` means
# the mount IS this directory itself (same shape as mission 05's
# /root/.ssh — no enclosing-directory indirection needed). No
# `plant-seed-source` header: /opt/nimbus/vault is a brand-new directory with
# no pre-existing content on the challenge image to restore first (unlike
# /etc, which mission 02/09 need populated with the rest of a realistic
# /etc). This mount is shared with 10-final-exfil/plant.sh, which also
# targets /opt/nimbus/vault (gen-values.sh dedupes the mount + mkdir -p, same
# structure as 03/10 previously sharing /etc — see that script's
# MOUNTDIR_KEYS handling). No `plant-mount-readonly` override either: unlike
# /etc, nothing needs to write into /opt/nimbus/vault at runtime, so it stays
# readOnly:true (fail-closed default).
#
# The vault file holds the flag ALONE (no comment prefix, no surrounding
# credential-file content) — `cat` on it prints exactly the flag and nothing
# else. Filename `creds.recover` is thematic for the Operation NimbusBreach
# narrative: a staged credential-recovery artifact an attacker would stash
# after harvesting secrets, consistent with 03's briefing (CTF Company SOC
# is watching /etc/shadow-style reads after mission 02; the same
# path-string-based Falco rule is made to also cover this vault file on the
# platform side, so the participant must reuse 03's own /proc/self/root
# technique instead of finding an unmonitored path "for free").
#
# platform-side dependency (cross-repo, same as ADR-0008/0017/0025-style
# customRules precedent): `Read sensitive file untrusted` must be extended
# via Falco `customRules` (append) to also match
# `fd.name = "/opt/nimbus/vault/creds.recover"` — this repo's falco-rule.yaml
# forbiddenRules stays "Read sensitive file untrusted" unchanged (same rule
# name, wider upstream condition), so no custom-falco-rules.txt entry is
# needed (that manifest is for NEW rule names only). Deploy order: platform's
# customRules append MUST land before this plant-target is live, or the
# naive `cat /opt/nimbus/vault/creds.recover` free-wins the mission with no
# detection at all (same failure mode ADR-0025 §Consequences documents for
# its own mission10 vault path).
#
# CTF_FLAG_03_STEALTH_READ is injected into the `plant` initContainer from the
# ctf-flags Secret (the chart supplies a FALCO{dev-...} default for local
# runs).
mkdir -p "${PLANT_SEED_ROOT}/opt/nimbus/vault"
printf '%s\n' "${CTF_FLAG_03_STEALTH_READ:?flag env not set by ctf-user chart}" > "${PLANT_SEED_ROOT}/opt/nimbus/vault/creds.recover"
