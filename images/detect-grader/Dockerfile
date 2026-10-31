# detect-grader — the 7th image (I5). Falco + a capture-replay grading
# entrypoint for `type: detect` challenges. Run as a per-submission Kubernetes
# Job by the scoreboard's K8sJob DetectRunner (design §3.1/§3.2).
#
# Build context: images/detect-grader (self-contained: entrypoint + curated
#   macros; the .scap capture fixtures are baked in Phase 44.2 — see
#   /opt/grader/captures below).
#
# Hardening (matches the Job's securityContext set by the client-go runner):
#   - runs as NON-ROOT UID 65532 (conventions UID table; aligns with
#     scoreboard/auth-policy/collector I2);
#   - replay is DRIVERLESS (engine.kind: replay) → no privilege, no kernel
#     driver, no network needed (deny-all NetworkPolicy supplied by platform);
#   - read-only rootfs compatible: the entrypoint writes only to a mktemp dir
#     under /tmp (emptyDir) and to /dev/termination-log (kubelet-provided).
#
# Supply chain (P12): the falco base is DIGEST-PINNED. Re-record captures and
# re-resolve this digest together when the Falco version bumps (capture format &
# field semantics can change — design §5).
#   digest resolved 2026-08-14 for falcosecurity/falco:0.44.1 (manifest list;
#   bumped from 0.43.1 to pick up base-image alpine package fixes — libcrypto3/
#   libssl3/busybox/jq CVEs; 0.43.1 has no patch tag (0.43.2/0.43.3 do not
#   exist) so this bumps to the next stable minor. `engine.kind: replay`
#   (driverless capture replay, used by grade.sh) is unaffected — verified the
#   config parses and falco starts under 0.44.1 before pinning):
#   docker buildx imagetools inspect falcosecurity/falco:0.44.1 --format '{{.Manifest.Digest}}'
FROM falcosecurity/falco:0.44.1@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b

# apk upgrade (#227): base の falcosecurity/falco:0.44.1 は digest を据え置く。
# 0.45.0 は 2026-09-21 に出ているが上げない: 上の通り Falco の版を上げるときは
# captures の再録と cluster の Falco (platform の chart) との整合を同時に取る必要が
# あり、CVE 修正のために単独で上げると grading が cluster の検知とずれる。追跡は
# app#344 (detect-grader を falco 0.45.0 へ)。この据え置き理由の見直しは app#567。
# この base は wolfi/apko 由来で apk toolchain を持つ (usr/bin/apk + usr/lib/apk/db を
# 確認済み)。libssl3/libcrypto3 3.6.3-r0 には CVE-2026-14456 (fix 3.6.3-r5) /
# CVE-2026-54876 (fix 3.6.3-r4) があり、明示 upgrade で解消する。
#
# **Exact version pin** (P12 と同じ規律 — 未 pin の `apk upgrade` は build 時の live
# APKINDEX に依存し bit-identical を壊す。#227)。版は apk.cgr.dev/chainguard の
# APKINDEX を base 内で `apk policy` 実測 (2026-10-13)、いずれも各 CVE の fix 版以上。
#
# curl / libcurl-openssl4 は **pin せず除去**する (2026-10-13、security review M1):
#   - grader は curl を使わない。grade.sh は http_output / grpc を無効にして
#     `falco -c ... -r ...` を replay 実行するだけ。
#   - falco バイナリは libcurl / libssl に動的リンクしていない
#     (`ld-linux --list /usr/bin/falco` = libm / libc / libpthread / libdl / librt のみ)。
#   - curl 8.22.0 へ `--upgrade` すると依存 33 pkg が動き、openssl 4.0 の
#     libcrypto/libssl と provider-legacy が新規に入って OpenSSL 3 と 4 が同居する。
#     除去すれば curl/libcurl の High/Medium が丸ごと消え、この問題も起きない。
# ca-certificates (package) は pin せず **除去**する (curl と同じ流儀、ttyd の app#517 と同型):
#   - 同 package が持つのは update-ca-certificates / c_rehash と mozilla の個別 .crt だけ。
#     grader はどれも呼ばない (grade.sh は falco replay のみ、network 無し)。他の package
#     も依存していない (`apk info -r ca-certificates` = 空)。
#   - 20260909-r2 以降の ca-certificates は `so:libcrypto.so.4` に依存する。pin して
#     upgrade すると curl の件と同じく OpenSSL 3 (libcrypto3 3.6.4) と 4 が同居する。
#   - 実際に TLS の trust store として読まれる /etc/ssl/certs/ca-certificates.crt は
#     ca-certificates-bundle 側の所有 (`apk info -W` で確認)。bundle は依存を持たない
#     ので exact pin で単独 upgrade できる (下の pin)。
# 他の pin (CI の scan / Sysdig の suggested fix 版に厳密一致):
#   ca-certificates-bundle  20260413-r0 -> 20260909-r3 (CI の scan の fix 版)
#   zlib             1.3.2-r3 -> 1.3.2.1_rc20260601-r0
#   glibc / glibc-locale-posix / ld-linux / libcrypt1   2.43-r8 -> 2.43-r10
RUN apk del --no-cache curl libcurl-openssl4 ca-certificates \
 && apk add --no-cache --upgrade \
        ca-certificates-bundle=20260909-r3 \
        libssl3=3.6.4-r0 libcrypto3=3.6.4-r0 \
        zlib=1.3.2.1_rc20260601-r0 \
        glibc=2.43-r10 glibc-locale-posix=2.43-r10 ld-linux=2.43-r10 libcrypt1=2.43-r10 \
 && ! apk info -e curl >/dev/null \
 && ! apk info -e libcurl-openssl4 >/dev/null \
 && ! apk info -e ca-certificates >/dev/null \
 && ! apk info -e openssl-4.0-libcrypto >/dev/null \
 && ! ls /usr/lib/libcrypto.so.4* /lib/libcrypto.so.4* >/dev/null 2>&1
# 上の 5 行は build 時の assert (失敗なら build が落ちる。ttyd の app#517 と同型)。curl /
# libcurl-openssl4 / ca-certificates package は置かない。OpenSSL 4 の libcrypto
# (package `openssl-4.0-libcrypto` / `libcrypto.so.4`) も置かない (OpenSSL 3 との同居を
# 作らない)。誰かが apk add に ca-certificates / curl を戻す (または引き込む package を
# 足す) と、ここで止まる。外向き TLS が要る道具を足すときは、先に消費者をここに書く。

# Create the non-root grader user (the wolfi/apko base ships no 65532 user).
# Done at build time as root; the container then runs as 65532 (USER below and
# the Job securityContext both pin it).
RUN printf 'grader:x:65532:65532:grader:/home/grader:/usr/bin/sh\n' >> /etc/passwd \
 && printf 'grader:x:65532:\n' >> /etc/group \
 && mkdir -p /home/grader /opt/grader/captures /input \
 && chown -R 65532:65532 /home/grader

# Grading entrypoint + curated macro vocabulary. macros.yaml MUST stay in lockstep
# with detect.curatedMacros in internal/scoreboard/detect/detect.go (see the file
# header). Captures are baked under /opt/grader/captures/<challengeId>/ in Phase
# 44.2; until then a mission with no baked captures fails closed (invalid) rather
# than mis-grading.
COPY grade.sh   /opt/grader/grade.sh
COPY macros.yaml /opt/grader/macros.yaml
RUN chmod 0555 /opt/grader/grade.sh /opt/grader/macros.yaml

ENV RULE_NAME=participant_detect \
    CONDITION_FILE=/input/condition \
    HOME=/home/grader

USER 65532:65532
ENTRYPOINT ["/usr/bin/sh", "/opt/grader/grade.sh"]
