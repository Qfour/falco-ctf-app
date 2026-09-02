# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG KUBECTL_VERSION=v1.35.8
# sha256 は https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/<arch>/kubectl.sha256
# の実値を焼き込み。KUBECTL_VERSION を上げたら両方更新すること。
#
# v1.36.4 -> v1.35.8 (2026-09-01, workspace#33 続報): platform 側で EKS
# extended support 終了 (1.30 は新規作成不可) が判明し、cluster_version を
# 1.34 へ bump する方針に変更。kubectl 公式 skew policy
# (https://kubernetes.io/releases/version-skew-policy/, apiserver ±1 minor)
# 上、cluster 1.34 に対する in-policy kubectl は 1.33-1.35 — v1.36.4 は
# skew+2 で NG になったため、範囲内の最新パッチ v1.35.8 (stable-1.35.txt
# 実測、v1.35.9 は 404 で不存在確認済み) へ down-bump。
#
# Go toolチェーン High 7 件 (CVE-2026-56862/-56853/-56860/-56858/-56859/
# -33818/-56864/-56865、fix = go1.26.6) は **本 bump では解消しない** —
# v1.35.8 の .go-version は 1.26.5 のまま (v1.36.4 と同じ)。skew policy が
# 1.33-1.35 に縛る一方、go1.26.6 を含む 1.35.x パッチはまだ存在しない
# (1.35 系は 1.36 系より先にブランチしたため toolchain 更新が遅行する)。
# x/net (v0.56.0) / x/text (v0.39.0) 由来の CVE-2026-46600/-39821/-56852
# は v1.35.8 の go.mod 時点で既に解消済み (CHANGELOG-1.35.md 実測) — 残る
# のは stdlib 本体 (crypto/tls 等) の 7 High のみ。skew policy 内で選べる
# 最善が v1.35.8 であり、残 CVE は accept 継続 (再点検トリガ: 1.35 系に
# go1.26.6 ベースのパッチが出る / cluster_version が再確定する)。
ARG KUBECTL_SHA256_AMD64=874d5e72dbb819f43cff16bcd1e4f8bac5b7f2361fe1e55049b0a6c676fb0cbf
ARG KUBECTL_SHA256_ARM64=cc749967b62f4422260bc9c0aa7a7c55f45175ae38cb8d95767b5d2b7e04c1fd

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
#   curl/libcurl 8.22.0-r0 (2026-09-03: alpine 3.24 リポジトリから 8.21.0-r0 が
#   既に外れ apk resolve が failing していたため再 pin。`apk policy curl` 実測
#   で 3.24/main の唯一の提供版が 8.22.0-r0 であることを確認済み)
#   bash 5.3.9-r1 (3.23 の 5.3.3-r1 から 3.24 側で上がった版に追随、念のため厳密 pin)
# ca-certificates / ttyd / tini の版数は 3.23→3.24 で不変 (live APKINDEX 実測、
# 2026-09-01) — 既存 pin をそのまま 3.24 リポジトリに再確認して引き継ぐ。
# kubectl (Go toolchain High) は本 alpine bump のスコープ外 — バージョン選定の
# 経緯は上の ARG KUBECTL_VERSION 直下のコメント (workspace#33) を参照。
RUN apk add --no-cache --upgrade libssl3=3.5.8-r0 libcrypto3=3.5.8-r0 \
 && apk add --no-cache \
        "ttyd=1.7.7-r0" \
        "bash=5.3.9-r1" \
        "ca-certificates=20260611-r0" \
        "curl=8.22.0-r0" \
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
