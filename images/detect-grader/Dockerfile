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

# apk upgrade (#227): no falcosecurity/falco tag newer than 0.44.1 exists yet
# (checked 2026-08-28 against the Docker Hub tag list), so there is no base
# digest to bump to. The wolfi/apko base still ships libssl3/libcrypto3
# 3.6.3-r0 (CVE-2026-14456 fix=3.6.3-r5, CVE-2026-54876 fix=3.6.3-r4, both
# High). This base DOES ship a usable apk toolchain (verified by inspecting
# the published image layers — usr/bin/apk + usr/lib/apk/db are present), so
# an explicit upgrade here picks up the fix without waiting for a new Falco
# release. **Exact version pin** (same discipline as the digest pin in P12 —
# an un-pinned `apk upgrade` depends on the live APKINDEX at build time and
# breaks bit-identical builds; flagged by security-engineer review and fixed
# here, #227). 3.6.4-r0 is the version confirmed by fetching
# https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz (measured 2026-08-28) —
# it is past both fix thresholds above.
RUN apk add --no-cache --upgrade libssl3=3.6.4-r0 libcrypto3=3.6.4-r0

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
