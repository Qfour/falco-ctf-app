# challenge base image — the playground users actually type into.
# Per-challenge fixtures are mounted/overlaid by the Helm chart at deploy time
# (see charts/ctf-user/templates/configmap-fixtures.yaml).
FROM alpine:3.20

# Tools commonly required by Falco-detection-style CTF challenges.
RUN apk add --no-cache \
        bash \
        coreutils \
        busybox-extras \
        curl \
        wget \
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

# Default sleep keeps the container alive; ttyd reaches it via kubectl exec.
CMD ["sleep", "infinity"]
