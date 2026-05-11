# ttyd container — serves a Web terminal that kubectl-exec's into the challenge
# container of the same Pod. Intended to run as a non-root user with a SA that
# has only `pods/exec` on this Pod's name.
FROM alpine:3.20

ARG KUBECTL_VERSION=v1.31.0

RUN apk add --no-cache \
        ttyd \
        bash \
        ca-certificates \
        curl \
        tini \
 && ARCH="$(uname -m)" \
 && case "${ARCH}" in \
        aarch64) ARCH=arm64 ;; \
        x86_64)  ARCH=amd64 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
 && chmod 0755 /usr/local/bin/kubectl \
 && adduser -D -u 1000 ttyd

USER 1000:1000

EXPOSE 7681

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
