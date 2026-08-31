# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

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

# alpine 3.22→3.23 bump (#227 2026-09-01 方針、workspace#31):
# curl の High CVE は 3.22 サイクルに fix apk が無く cycle bump でのみ解消した
# (live APKINDEX 実測、2026-09-01)。**厳密バージョン pin** (他パッケージと同じ
# 規律。P12 の digest pin と同じ思想 — 未 pin の `apk add`/`apk upgrade` は build
# 時点の live APKINDEX に依存し bit-identical を壊すため)。以下は
# https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz を
# 実測して確認した版数 (2026-09-01):
#   libssl3/libcrypto3 3.5.8-r0 (base に焼き込まれた 3.5.7-r0 の fix 版。3.23 でも
#     base image 自体は再ビルドされていないため引き続き明示 upgrade が必要)
#   curl 8.20.0-r0 (fix >= 8.18.0 を満たす。旧 8.14.1-r3 の
#     CVE-2026-5773/-6276/2025-14017/-13034 を解消)
#   bash 5.3.3-r1 (念のため厳密 pin。既存 pin 対象への追加)
# ca-certificates / ttyd / tini の版数は 3.22→3.23 で不変 (live APKINDEX 実測、
# 2026-09-01) — 既存 pin をそのまま 3.23 リポジトリに再確認して引き継ぐ。
# kubectl (Go toolchain High) は本 bump のスコープ外 — v1.36→v1.37 は EKS skew
# 確認要のため別 brief (workspace#31 brief 記載どおり)。
RUN apk add --no-cache --upgrade libssl3=3.5.8-r0 libcrypto3=3.5.8-r0 \
 && apk add --no-cache \
        "ttyd=1.7.7-r0" \
        "bash=5.3.3-r1" \
        "ca-certificates=20260611-r0" \
        "curl=8.20.0-r0" \
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
