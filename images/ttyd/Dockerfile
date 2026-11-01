# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
# --- Stage 1: kubectl (build only) ---------------------------------------------
# kubectl の取得と sha256 検証は、この build stage だけで行う。runtime に持ち込むのは
# 検証済みの 1 ファイルだけ (COPY --from)。取得に使う道具 (busybox wget) は alpine base
# に標準で入っており、apk add は 1 つも要らない (= 新しい pin が増えない)。runtime stage
# に curl / libcurl が残らない (app#382 の security 同意コメント (2026-10-25) の F6 / app#504: ttyd は pods/exec の SA token を
# 持つコンテナなので、使わない package は置かない)。
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS kubectl

ARG KUBECTL_VERSION=v1.35.10
# v1.35.9 -> v1.35.10 (2026-11-01, main の build (ttyd)/scan 赤の追跡、app#291): 10-25 の
# 再点検で未公開だった v1.35.10 が公開された (stable-1.35.txt = v1.35.10)。skew policy 内
# (cluster 1.34 に対し 1.33-1.35) を維持したまま patch だけ上げる。v1.35.10 の
# .go-version は 1.26.10 (v1.35.9 は 1.26.8) — 取得した binary の buildinfo でも go1.26.10
# を確認済み (amd64 / arm64 とも)。Go toolchain / stdlib 由来の指摘 (GO-2026-6809
# crypto/x509 など、fix が go1.26.10 以下のもの) はこれで解消する見込み。
# **残存 (未達)**: golang.org/x/net は v0.56.0、golang.org/x/text は v0.39.0 のまま
# (両 arch の buildinfo 実測。v1.35.10 / v1.34.13 / v1.36.6 の go.mod と release-1.35 の
# head も同じ版)。Sysdig の x/net fix は v0.60.0 (GO-2026-6617) なので、x/net 由来の
# 指摘 (Critical / High) と x/text の指摘は残る見込みで、build (ttyd)/scan は赤のままの見込み —
# upstream の patch 待ち (下の解除条件)。skew policy 外の minor (1.36 系) へ上げても
# 同じ x/net で解消しないため、版を動かさずに bump 条件の成立を待つ。
# **受け入れの期限と解除条件 (2026-11-01 更新、2026-10-13 起点)**: kubectl の x/net が
# v0.60.0 以上になった時点 (Go 側の 1 条件目 = release-1.35 の .go-version が 1.26.10
# 以上は v1.35.10 で達成済み) で bump する。**再点検の期限は次の stand-up の前**。
# それまで build (ttyd)/scan は赤のまま (required check ではない)。追跡: app#338。
# sha256 は dl.k8s.io/release/v1.35.10/bin/linux/<arch>/kubectl.sha256 の実値で、
# 取得した binary の shasum とも一致を確認した。
#
# v1.35.8 -> v1.35.9 (2026-10-13): v1.35.9 が公開された (v1.35.8 節で「404 で不存在」と
# 確認した版)。v1.35.9 の .go-version は 1.26.8 (v1.35.8 は 1.26.5)、x/net v0.56.0。
# 再点検 (2026-10-25): v1.35.10 の kubectl.sha256 は 404、release-1.35 の .go-version
# は既に 1.26.10 だったが x/net は v0.56.0。
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
ARG KUBECTL_SHA256_AMD64=c49a28f1f4efc4d475ed05f47f2ce8e563bf7bef69ed77fe1b924ea6d83b6327
ARG KUBECTL_SHA256_ARM64=283f1be6a46b3695b625e25030106b8ffe18bd0d3a900f5b65c259ca407f04f5
RUN ARCH="$(uname -m)" \
 && case "${ARCH}" in \
        aarch64) ARCH=arm64; SHA256="${KUBECTL_SHA256_ARM64}" ;; \
        x86_64)  ARCH=amd64; SHA256="${KUBECTL_SHA256_AMD64}" ;; \
        *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
 && wget -q -O /kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
 && echo "${SHA256}  /kubectl" | sha256sum -c - \
 && chmod 0755 /kubectl

# --- Stage 2: runtime ----------------------------------------------------------
# runtime に入る package は ttyd / tini (+ libssl3 / libcrypto3 / zlib の
# 明示 upgrade) だけ (ca-certificates も入れない: app#517、下のコメント)。
# bash と curl / libcurl は **無い** (app#504): bash は
# `kubectl exec -c challenge ... /bin/bash -l` の引数で challenge container 側で動き、
# curl は readinessProbe だったが busybox wget に替えた (charts/ctf-user/templates/pod.yaml)。
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

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
#   ca-certificates は **入れない** (app#517、2026-10-26。以前は 20261020-r0 を pin
#     していたが、10-05 と 10-25 の drift 2 回の原因だった)。runtime に消費者が無い:
#     (a) kubectl は in-cluster config の CAFile に SA の ca.crt を使い system の CA store を
#     見ない (entrypoint.sh:16-17。charts/ctf-user/templates/pod.yaml の ttyd-sa-token
#     volume (:405-415、kube-root-ca.crt の ca.crt の投影) を ttyd container が
#     /var/run/secrets/kubernetes.io/serviceaccount に mount する (:235))、(b) ttyd は loopback の plain HTTP (--ssl なし、TTYD_INTERFACE=127.0.0.1)、
#     (c) readinessProbe の busybox wget も http://127.0.0.1。build stage の dl.k8s.io (https)
#     は stage 1 の base の ca-certificates-bundle で足りる。runtime の base にも
#     ca-certificates-bundle は標準で入っている (alpine の既定。外れるのは
#     `ca-certificates` package だけで、bundle の更新は base digest の引き上げで行う)。
#     runtime で外向き TLS が要る道具を足すときは、その道具の消費者をここに書いてから戻す)
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
        "tini=0.19.0-r3" \
 && adduser -D -u 1000 ttyd \
 && command -v wget >/dev/null \
 && ! command -v curl >/dev/null \
 && ! command -v bash >/dev/null \
 && ! apk info -e ca-certificates >/dev/null
# 上の 4 行は build 時の assert (失敗なら build が落ちる)。chart の ttyd readinessProbe
# (charts/ctf-user/templates/pod.yaml) が busybox wget に依存し (wget あり)、curl / bash は
# runtime に置かない (#504)、ca-certificates package も置かない (#517。base の
# ca-certificates-bundle は残る)。誰かが apk add に curl / bash / ca-certificates を戻す
# (または引き込む package を足す) と、ここで止まる。

COPY --from=kubectl --chmod=0755 /kubectl /usr/local/bin/kubectl

USER 1000:1000

# EXPOSE stays the historical port for backward compat (image default
# TTYD_PORT/TTYD_INTERFACE are unchanged — see entrypoint.sh). The ctf-user
# chart opts in to the P23-3 topology by setting TTYD_PORT to
# .Values.ttyd.upstreamPort (7682) + TTYD_INTERFACE=127.0.0.1, then fronts
# ttyd with the ttyd-proxy sidecar on this historical Ingress port (7681).
EXPOSE 7681

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
