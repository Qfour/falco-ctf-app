# challenge base image — the playground users actually type into.
#
# Build context: **repo root** (so `challenges/` is reachable as a
# build context path). Per-challenge fixtures are still mountable via
# the Helm chart's ConfigMap for legacy single-mission deploys, but
# all-missions mode reads from the image-baked /opt/ctf/missions/
# directory below.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

# Tools commonly required by Falco-detection-style CTF challenges.
#
# wget: GNU wget パッケージは入れない。alpine 3.22-main の wget-1.25.0-r1 は
# Critical CVE (CVE-2025-69194 ほか) 未修正で、3.22 サイクルに fix apk が無い
# (apk upgrade/pin で解消不可)。base busybox が /usr/bin/wget を提供し、
# `wget -q -O- --no-check-certificate https://...` (課題 01 の自己署名 k8s API 叩き)
# を含む課題用途は busybox wget で動作確認済み (--no-check-certificate も honor)。
# → 脆弱バイナリを除去 = Critical を実解消 (例外で握り潰さない、P13/#18 の CEO 条件)。
RUN apk add --no-cache \
        bash \
        coreutils \
        busybox-extras \
        curl \
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

# Mission 09 retarget fixture (ADR-0001 §派生決定(2), 09-ii): a stock,
# realistic-looking /etc/sudoers so `ln /etc/sudoers <target>` has something
# to hardlink that isn't a bind-mounted plant-target (mission 09's original
# `/etc/shadow` target became a separate mount under Option B, so `link()`
# across it returns EXDEV — see charts/ctf-user/templates/pod.yaml and
# .claude/agents/challenge-author.md). /etc/sudoers is already in the docs
# site's displayed `sensitive_file_names` list (challenges/*/rule.yaml) but
# was never actually present in this image (no sudo package) until now.
# Carries no real credential (I10) — a boilerplate sudoers body, not planted,
# not per-user, identical on every image build.
RUN printf '%s\n' \
      '# /etc/sudoers — CTF fixture (not planted, not per-user)' \
      '' \
      'Defaults        env_reset' \
      'root ALL=(ALL:ALL) ALL' \
      '%wheel ALL=(ALL:ALL) ALL' \
      > /etc/sudoers \
 && chown root:root /etc/sudoers \
 && chmod 0440 /etc/sudoers

# ADR-0001 (Option B, S-a): bake a build-time snapshot of this image's own
# /etc/shadow into a non-sensitive path. At deploy time, the `plant`
# initContainer (charts/ctf-user/templates/pod.yaml, generated seed script
# from challenges/gen-values.sh) copies FROM here — never from the real
# /etc/shadow — so the deploy path never reads a path matching the
# `sensitive_files` Falco macro (fd.name startswith /etc and in
# sensitive_file_names; challenges/03-stealth-read/rule.yaml:90-93). This
# snapshot introduces ZERO new material (I10): it's a byte-for-byte copy of
# the shadow file this same image already ships — measured (2026-08-18,
# architect + security-engineer, independently reproduced) to be 0640
# root:shadow, 17 lines, all locked (`*` / `!`), 0 crypt-hash-shaped strings.
# `make check-image-hygiene` (ADR-0001 DoD 15, not yet landed) is meant to
# re-verify this at every build so a future package addition that puts a
# real hash into /etc/shadow fails the build instead of silently baking it
# into the snapshot; until that lands, this comment is the only guard.
RUN mkdir -p /opt/ctf/plant-seed/etc \
 && cp -a /etc/shadow /opt/ctf/plant-seed/etc/shadow

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
COPY challenges/setname.sh /opt/ctf/setname.sh
COPY challenges/submit-yaml.sh /opt/ctf/submit-yaml.sh
COPY challenges/banner.sh /opt/ctf/banner.sh
RUN chmod 0644 /opt/ctf/submit.sh /opt/ctf/setname.sh /opt/ctf/submit-yaml.sh /opt/ctf/banner.sh

# answers.yaml — editable template for batch submission. Auto-listed from the
# EVADE missions (the only ones needing a flag); trigger missions are omitted.
RUN { echo '# EVADE 課題で読み取ったフラグを記入し、submit-yaml で一括提出:'; \
      echo '#   sh /opt/ctf/submit-yaml.sh'; \
      echo '# trigger 課題は提出不要(Falco 発火で自動 solve)。'; \
      for f in /opt/ctf/missions/[0-9][0-9]-*/falco-rule.yaml; do \
        if grep -q 'type:[[:space:]]*evade' "$f"; then \
          id=$(awk '/^challengeId:/{print $2}' "$f"); echo "${id}: "; \
        fi; \
      done; } > /opt/ctf/answers.yaml

# Greet on login. Briefing/hints/flag submission all happen in the Story tab
# (portal), not in-terminal, so banner.sh is intentionally minimal
# (display-name change only).
RUN echo 'sh /opt/ctf/banner.sh 2>/dev/null' >> /etc/profile

# Default sleep keeps the container alive; ttyd reaches it via kubectl exec.
CMD ["sleep", "infinity"]
