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

# Greet on login. banner.sh builds the docs/scoreboard URLs from
# $FALCO_CTF_DNS_SUFFIX (set by the ctf-user chart) so the same image serves
# local + prod. Docs (briefs/hints/PDF) live on the docs site, not in-terminal.
RUN echo 'sh /opt/ctf/banner.sh 2>/dev/null' >> /etc/profile

# Default sleep keeps the container alive; ttyd reaches it via kubectl exec.
CMD ["sleep", "infinity"]
