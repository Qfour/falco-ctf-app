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
#   digest resolved 2026-08-11 for falcosecurity/falco:0.43.1 (manifest list):
#   docker buildx imagetools inspect falcosecurity/falco:0.43.1 --format '{{.Manifest.Digest}}'
FROM falcosecurity/falco:0.43.1@sha256:b4166a61f41e2fa638c041cac881d8bb32c284e3aaf282fdfed80f15f6eb55e3

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
