# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

ARG KUBECTL_VERSION=v1.36.2
# sha256 は https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/<arch>/kubectl.sha256
# の実値を焼き込み。KUBECTL_VERSION を上げたら両方更新すること。
ARG KUBECTL_SHA256_AMD64=1e9045ec32bea85da43de85f0065358529ea7c7a152eca78154fba5b58c27d82
ARG KUBECTL_SHA256_ARM64=c957eb8c4bea27a3bb35b269edd9082e27f027f7b76b20b5bf4afebc726c6d3e

RUN apk add --no-cache \
        "ttyd=1.7.7-r0" \
        "bash=5.2.37-r0" \
        "ca-certificates=20260611-r0" \
        "curl=8.14.1-r2" \
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

EXPOSE 7681

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
