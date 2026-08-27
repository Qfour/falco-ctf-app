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
#
# apk upgrade (#227): alpine:3.22 タグは 2026-08-14 の pin 以降リビルドされて
# おらず (index digest 不変・実測確認済み)、base に焼き込まれた libssl3/libcrypto3
# は 3.5.7-r0 のまま (CVE-2026-63072..63076/-54874/-18798/-14456/-14457, High)。
# v3.22/main の APKINDEX は既に 3.5.8-r0 (fix 版) を配布しているため明示 upgrade
# で解消する。**この画像には残る High CVE がある** (v3.22 の apk リポジトリに
# バックポートがまだ無いため apk upgrade では解消不可):
#   curl/libcurl 8.14.1-r3 (fix >= 8.18.0, CVE-2026-5773/-6276/2025-14017/-13034)
#   vim/vim-common/xxd 9.1.1566-r0 (fix は 9.2.x 系列 — マイナー系列を跨ぐ、23件)
#   jq 1.8.1-r0 (fix 1.8.2, CVE-2026-49839)
#   libxml2 2.13.9-r1 (fix 2.15.2, CVE-2026-0989/2025-8732; CVE-2026-11979 は
#     upstream に fix 自体が存在しない)
# 上記は Issue #227 に残課題として記録 (VP 判断待ち — apk pin ではなく alpine
# サイクル bump か、パッケージ除去/代替が必要になる可能性がある)。
RUN apk upgrade --no-cache libssl3 libcrypto3 \
 && apk add --no-cache \
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

# ADR-0007 (Option 1, supersedes the file-granularity snapshot from
# ADR-0001 S-a): bake a build-time snapshot of this image's own /etc
# DIRECTORY (not just /etc/shadow) into a non-sensitive path. At deploy
# time, the `plant` initContainer (charts/ctf-user/templates/pod.yaml,
# generated seed script from challenges/gen-values.sh) restores this whole
# directory into the seed emptyDir with `cp -a .../etc/. $SEED/etc/` before
# any mission's plant.sh appends to a file inside it — never reading the
# real /etc at runtime — so the deploy path never reads a path matching the
# `sensitive_files` Falco macro (fd.name in sensitive_file_names;
# challenges/03-stealth-read/rule.yaml). Directory (not file) granularity is
# required because `open_read`-family Falco rules only match
# `fd.typechar='f'` (a directory open can never satisfy them) — see
# docs/adr/0007-plant-mount-directory-granularity.md §C2 for the real-
# cluster probe that found this. This snapshot introduces ZERO new material
# (I10): it's a byte-for-byte copy of the whole /etc this same image already
# ships (mode/owner preserved by `cp -a`) — verified at every build by
# `make check-image-hygiene` (ADR-0001 DoD 15 / ADR-0007 Verification 3),
# which fails the build if any file's hash/flag-shaped content or
# mode/owner/entry-set diverges from the real /etc it shadows.
#
# THIS MUST BE THE LAST RUN THAT TOUCHES /etc IN THIS DOCKERFILE — anything
# that modifies /etc after this line would silently drift the snapshot from
# the real /etc the challenge container actually ships (check-image-hygiene
# catches the drift at build time, but keeping this line last avoids
# depending on that safety net in the first place).
RUN mkdir -p /opt/ctf/plant-seed/etc \
 && cp -a /etc/. /opt/ctf/plant-seed/etc/

# Default sleep keeps the container alive; ttyd reaches it via kubectl exec.
CMD ["sleep", "infinity"]
