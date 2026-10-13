# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG KUBECTL_VERSION=v1.35.9
# v1.35.8 -> v1.35.9 (2026-10-13, CI scan 全 PR 赤の追跡): v1.35.9 が公開された
# (下の v1.35.8 節で「404 で不存在」と確認した版)。skew policy 内 (cluster 1.34 に
# 対し 1.33-1.35) を維持したまま patch だけ上げる。v1.35.9 の .go-version は 1.26.8
# (v1.35.8 は 1.26.5)。sha256 は dl.k8s.io/release/v1.35.9/bin/linux/<arch>/kubectl.sha256
# の実値。**残存**: Sysdig の fix は Go 1.26.9 / golang.org/x/net v0.60.0 (GO-2026-6617)
# だが、kubectl は v1.35.9 (go1.26.8, x/net v0.56.0) / v1.36.5 (go1.26.8, x/net v0.56.0) /
# v1.37.1 (go1.26.8, x/net v0.57.0) のいずれも未達 — upstream の patch 待ち
# **受け入れの期限と解除条件 (2026-10-13)**: release-1.35 の .go-version が 1.26.9 以上
# (v1.35.10 以降) になった時点で bump する。それまで build (ttyd)/scan は赤のまま
# (required check ではない)。追跡: app#338。
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
ARG KUBECTL_SHA256_AMD64=3cfeaf80be482b435b0aa214aff6e0b2c312ee23c0ff20810c75517b6004c6eb
ARG KUBECTL_SHA256_ARM64=39c98bca82875d9a9ddfb6f3c5ab17c3f78ea0801230683e538a67d5c053308d

# alpine 3.23→3.24 re-bump (#227 2026-09-01 続報、workspace#31):
# 3.23 bump 後の scan で curl/libcurl だけ drift した — pin 時点 (2026-09-01 午前)
# は 8.20.0-r0 が fix だったが、Sysdig の CVE フィードが同日中に 8.21.0 要求へ
# 更新され、8.20.0-r0 は再び High 扱いになった。3.23 リポジトリには 8.21.0-r0 が
# 無いため cycle bump (3.23→3.24) でのみ解消できる。以下は
# https://dl-cdn.alpinelinux.org/alpine/v3.24/main (community は ttyd/tini/vim
# 系) を `docker run alpine@<digest> apk policy` で実測して確認した版数
# (2026-09-01):
#   libssl3/libcrypto3 3.5.9-r0 (2026-10-05: 3.24/main から 3.5.8-r0 が外れ apk
#     resolve が failing していたため再 pin。`apk policy libssl3 libcrypto3` 実測で
#     3.24/main の唯一の提供版が 3.5.9-r0。base に焼き込まれた 3.5.7-r0 からの
#     明示 upgrade は引き続き必要。3.5.8-r0 の secfix [CVE-2026-63072..63076/
#     -54874/-18798/-14456/-14457/-75803, secdb v3.24/main] は 3.5.9 に累積で
#     含まれる — 上流 CHANGES.md の 3.5.7→3.5.8 節が 3.5.9 に残ることを aports と
#     併せて確認済み (5x R1)。3.5.9 自体も追加の CVE 修正を含む
#     (High は CVE-2026-84782))
#   curl/libcurl 8.22.0-r0 (2026-09-03: alpine 3.24 リポジトリから 8.21.0-r0 が
#   既に外れ apk resolve が failing していたため再 pin。`apk policy curl` 実測
#   で 3.24/main の唯一の提供版が 8.22.0-r0 であることを確認済み)
#   bash 5.3.9-r1 (3.23 の 5.3.3-r1 から 3.24 側で上がった版に追随、念のため厳密 pin)
#   ca-certificates 20260909-r0 (2026-10-05: 3.24/main から 20260611-r0 が外れた
#     ため再 pin。`apk policy ca-certificates` 実測で唯一の提供版。base 由来の
#     ca-certificates-bundle 20260611-r0 は pin 外で同居するが、bundle の中身は
#     ビルド時に新データで再生成される (5x R2 実測: 119→121 件、TLS 動作確認済み))
# ttyd / tini の版数は 3.23→3.24 で不変 (live APKINDEX 実測、2026-09-01。
# 2026-10-05 の `apk policy` 再実測でも 1.7.7-r0 / 0.19.0-r3 のまま)。
# zlib 1.3.2-r1 (2026-10-13: base digest を 3.24 の最新 294b683c へ更新。base に
#   焼き込まれた zlib は 1.3.2-r0 のままで Sysdig が High を出すため明示 upgrade。
#   `apk policy zlib` 実測で 3.24/main が 1.3.2-r1 を提供)
# kubectl (Go toolchain High) は本 alpine bump のスコープ外 — バージョン選定の
# 経緯は上の ARG KUBECTL_VERSION 直下のコメント (workspace#33) を参照。
RUN apk add --no-cache --upgrade libssl3=3.5.9-r0 libcrypto3=3.5.9-r0 zlib=1.3.2-r1 \
 && apk add --no-cache \
        "ttyd=1.7.7-r0" \
        "bash=5.3.9-r1" \
        "ca-certificates=20260909-r0" \
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
