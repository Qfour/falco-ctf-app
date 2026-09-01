# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG KUBECTL_VERSION=v1.36.4
# sha256 は https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/<arch>/kubectl.sha256
# の実値を焼き込み。KUBECTL_VERSION を上げたら両方更新すること。
# v1.36.2 -> v1.36.4 (2026-08-28, #227): CHANGELOG-1.36.md の "Update
# golang.org/x/text and golang.org/x/net dependencies to include security
# updates" (kubernetes/kubernetes#141226) が golang.org/x/net v0.49.0->v0.56.0
# (CVE-2026-46600/-39821/-33814) と golang.org/x/text v0.33.0->v0.39.0
# (CVE-2026-56852) を解消。.go-version も 1.26.4->1.26.5 に上がるが、Go 本体の
# stdlib CVE (CVE-2026-56862 ほか、fix = go1.26.6) は v1.36.4 時点でも未解消
# のまま残る (stable-1.36 の最新パッチが v1.36.4 — 2026-08-28 時点で確認)。
ARG KUBECTL_SHA256_AMD64=8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a
ARG KUBECTL_SHA256_ARM64=0ecf44450ee6063bf19dd166a103ee6df4a9034455c2abce626e6eea657d73fb

# alpine 3.23→3.24 re-bump (#227 2026-09-01 続報、workspace#31):
# 3.23 bump 後の scan で curl/libcurl だけ drift した — pin 時点 (2026-09-01 午前)
# は 8.20.0-r0 が fix だったが、Sysdig の CVE フィードが同日中に 8.21.0 要求へ
# 更新され、8.20.0-r0 は再び High 扱いになった。3.23 リポジトリには 8.21.0-r0 が
# 無いため cycle bump (3.23→3.24) でのみ解消できる。以下は
# https://dl-cdn.alpinelinux.org/alpine/v3.24/main (community は ttyd/tini/vim
# 系) を `docker run alpine@<digest> apk policy` で実測して確認した版数
# (2026-09-01):
#   libssl3/libcrypto3 3.5.8-r0 (3.23 と同じ pin を維持。base に焼き込まれた
#     3.5.7-r0 の fix 版で、3.24 でも base image 自体は再ビルドされていないため
#     引き続き明示 upgrade が必要)
#   curl/libcurl 8.21.0-r0 (fix。8.20.0-r0 で再発した High を解消)
#   bash 5.3.9-r1 (3.23 の 5.3.3-r1 から 3.24 側で上がった版に追随、念のため厳密 pin)
# ca-certificates / ttyd / tini の版数は 3.23→3.24 で不変 (live APKINDEX 実測、
# 2026-09-01) — 既存 pin をそのまま 3.24 リポジトリに再確認して引き継ぐ。
# kubectl (Go toolchain High) は本 bump のスコープ外 — v1.36→v1.37 は EKS skew
# 確認要のため別 brief (workspace#31 brief 記載どおり)。
#
# workspace#33 skew 確認 (2026-09-01 実施、NG — v1.36.4 のまま維持):
# terraform/providers/eks/variables.tf の kubernetes_version default (実 tfvars
# 無し、EKS teardown 中につきこれが唯一の実運用想定値) = "1.30"。kubectl の
# 公式 version skew policy (https://kubernetes.io/releases/version-skew-policy/)
# は kube-apiserver ±1 minor のみ対応。v1.37 (skew 7) はもちろん、現行 v1.36.4
# (skew 6) も既にポリシー外 — kubectl-exec のみの利用なので実害は未確認だが、
# 次回 cluster_version 決定時に kubectl 側の追随可否を再評価すること
# (再点検トリガは workspace#33 に準拠: EKS 実クラスタ確定 / 次回 stand-up)。
RUN apk add --no-cache --upgrade libssl3=3.5.8-r0 libcrypto3=3.5.8-r0 \
 && apk add --no-cache \
        "ttyd=1.7.7-r0" \
        "bash=5.3.9-r1" \
        "ca-certificates=20260611-r0" \
        "curl=8.21.0-r0" \
        "tini=0.19.0-r3" \
 && ARCH="$(uname -m)" \
 && case "${ARCH}" in \
        aarch64) ARCH=arm64; SHA256="${KUBECTL_SHA256_ARM64}" ;; \
        x86_64)  ARCH=amd64; SHA256="${KUBECTL_SHA256_AMD64}" ;; \
        *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
 && echo "${SHA256}  /usr/local/bin/kubectl" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/kubectl \
 && adduser -D -u 1000 ttyd

USER 1000:1000

# EXPOSE stays the historical port for backward compat (image default
# TTYD_PORT/TTYD_INTERFACE are unchanged — see entrypoint.sh). The ctf-user
# chart opts in to the P23-3 topology by setting TTYD_PORT to
# .Values.ttyd.upstreamPort (7682) + TTYD_INTERFACE=127.0.0.1, then fronts
# ttyd with the ttyd-proxy sidecar on this historical Ingress port (7681).
EXPOSE 7681

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
