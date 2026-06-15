# challenge base image — the playground users actually type into.
#
# Build context: **repo root** (so `challenges/` is reachable as a
# build context path). Per-challenge fixtures are still mountable via
# the Helm chart's ConfigMap for legacy single-mission deploys, but
# all-missions mode reads from the image-baked /opt/ctf/missions/
# directory below.
FROM alpine:3.20

# Tools commonly required by Falco-detection-style CTF challenges.
RUN apk add --no-cache \
        bash \
        coreutils \
        busybox-extras \
        curl \
        wget \
        netcat-openbsd \
        bind-tools \
        jq \
        less \
        vim \
        util-linux \
        procps \
        grep \
        findutils \
        file \
        shadow \
        ca-certificates \
 && echo 'PS1="\u@\h:\w\$ "' >> /etc/profile

# Bake the 10 missions + cross-mission helpers into the image. This is
# the source-of-truth for all-missions mode (deploy-user.sh <user> all):
# the workspace pod has every welcome.txt + fixture available from
# the first second of its life, no operator switching between missions.
#
# INTENTIONAL (guided-event decision, 2026-06): the whole challenges/ tree is
# baked, including README.md (想定解) and falco-rule.yaml. This is a guided
# learning event, not a blind competition — participants are allowed to read
# briefs/solutions. If this ever becomes competitive, exclude operator/author
# files here (README.md / falco-rule.yaml / plant.sh / values*.yaml).
COPY challenges/ /opt/ctf/missions/
COPY challenges/submit-all.sh /opt/ctf/submit.sh
RUN chmod 0644 /opt/ctf/submit.sh

# Quick orientation at login. Printed by /etc/profile additions below.
RUN printf '%s\n' \
  '┌─ Operation NimbusBreach — 10 missions ─────────────────────────┐' \
  '│ Read each mission brief in order:                              │' \
  '│                                                                │' \
  '│   cat /opt/ctf/missions/01-initial-recon/fixtures/welcome.txt  │' \
  '│   cat /opt/ctf/missions/02-credential-files/fixtures/welcome.txt│' \
  '│   cat /opt/ctf/missions/03-stealth-read/fixtures/welcome.txt   │' \
  '│   ...                                                          │' \
  '│                                                                │' \
  '│ Submit (evade challenges only):                                │' \
  '│                                                                │' \
  '│   source /opt/ctf/submit.sh                                    │' \
  '│   submit <mission-id> '"'"'<flag>'"'"'                                 │' \
  '│                                                                │' \
  '│ Reference card:                                                │' \
  '│   cat /opt/ctf/missions/REFERENCE.md                           │' \
  '│                                                                │' \
  '│ Participant handbook (pre-event reading):                      │' \
  '│   cat /opt/ctf/missions/PARTICIPANT-HANDBOOK.md                │' \
  '└────────────────────────────────────────────────────────────────┘' \
  > /opt/ctf/INDEX.txt

# Greet on login so participants always see the entry point.
RUN echo 'cat /opt/ctf/INDEX.txt 2>/dev/null' >> /etc/profile

# Default sleep keeps the container alive; ttyd reaches it via kubectl exec.
CMD ["sleep", "infinity"]
