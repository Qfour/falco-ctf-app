# docs site image — MkDocs Material (participant + 運営 builds), served by nginx.
#
# Build context: **repo root** (so the canonical `challenges/` tree is reachable;
# gen-pages.py renders one page per challenge from it — no committed duplication).
#   docker build --platform linux/amd64 -t <reg>/docs:<tag> -f images/docs/Dockerfile .
#
# Supply chain (P12/#227): both base digests below bumped 2026-08-28 (index
# digest re-resolved via `docker buildx imagetools inspect <image>:<tag>` — the
# tag itself did not move, but upstream re-published a new index digest under
# it, which is the mechanism that actually carries package-level CVE fixes
# such as libssl3/libcrypto3 3.5.7-r0 -> 3.5.8-r0, CVE-2026-63072..63076 /
# 54874 / 18798 / 14456 / 14457 — see Issue #227).
FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS build

RUN pip install --no-cache-dir "mkdocs-material==9.5.39"

WORKDIR /build
COPY challenges/ ./challenges/
COPY docs-site/ ./docs-site/

WORKDIR /build/docs-site
# Build twice from the same source. gen-pages.py decides what each page contains:
#   participant → /site        (brief only — no 想定解/解説)
#   admin       → /site-admin  (brief + 攻略と解説; 運営専用)
RUN for mode in participant admin; do \
        out=/site; name="Falco CTF — 課題ドキュメント"; \
        if [ "$mode" = admin ]; then out=/site-admin; name="Falco CTF — 課題ドキュメント (運営用)"; fi; \
        python3 gen-pages.py .. "$mode" \
     && DOCS_SITE_NAME="$name" mkdocs build --strict -d "$out" \
     && echo "[$mode] built -> $out"; \
    done

# ── serve ───────────────────────────────────────────────────────────
# nginx-unprivileged listens on 8080 as a non-root user (uid 101) — fits
# runAsNonRoot without extra config.
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:93722936b82ec8a1178d48448e619226680d2de3706a1640800e186cd5fa7fd3

# apk upgrade (#227 follow-up, 2026-08-28): PR #228 CI (build (docs) / scan)
# measured 21 High CVEs surviving the digest bump above, ALL attributed to
# this serve stage (Sysdig COMPONENT table: libcrypto3/libssl3/libxml2, all
# `Package/os` type — i.e. Alpine packages baked into nginx-unprivileged, not
# the python:3.12-slim/debian build stage discarded above; that stage
# contributed zero findings, so the earlier hypothesis that debian packages
# were the residue was wrong).
#
# nginxinc/nginx-unprivileged:1.30-alpine is itself built FROM alpine:3.24
# (not 3.22 — confirmed via nginxinc/docker-nginx's stable/alpine-slim/Dockerfile
# on 2026-08-28), so its installed libssl3/libcrypto3 (3.5.7-r0) predates the
# same 3.5.8-r0 fix as challenge/ttyd (CVE-2026-63072..63076/-54874/-18798/
# -14456/-14457, High) but must be pinned against v3.24's own APKINDEX, not
# v3.22's. **Exact version pin** (same discipline as challenge/ttyd/
# detect-grader — untraced `apk upgrade` breaks bit-identical builds, #227).
# 3.5.8-r0 confirmed present in
# https://dl-cdn.alpinelinux.org/alpine/v3.24/{main,community}/x86_64/APKINDEX.tar.gz
# (measured 2026-08-28) and matches Sysdig's suggested fix version exactly.
#
# libxml2 (installed 2.13.9-r2, 3 High CVEs) is NOT pinned here: v3.24's live
# APKINDEX still only serves 2.13.9-r2 (identical to installed — no newer
# build exists yet in either v3.22 or v3.24 stable), so Sysdig's suggested
# fix (2.15.2, a MINOR-version jump) is not resolvable via `apk add =<ver>`
# today regardless of Sysdig's own fixable/not-fixable classification per
# CVE. Residual — same "Alpine hasn't backported yet" category as challenge's
# libxml2 finding (CVE-2026-11979 among the 3 has no upstream fix released at
# all; the other two have a fix release but not yet an Alpine package build).
# Tracked by the #227 re-check triggers already recorded in that Issue.
#
# security-engineer BLOCKING review (2026-08-28): this base's `Config.User` is
# `101` (confirmed via `GET /v2/nginxinc/nginx-unprivileged/blobs/<config
# digest>` on the registry — non-root already, no explicit USER line needed
# it before this change). `apk` writes to /lib/apk/db (root-owned, 0755), so
# running the upgrade as 101 fails with a permission error. Wrap it in
# `USER root` / `USER 101` so the apk write happens as root but the final
# image still executes as 101, preserving nginx-unprivileged's non-root
# model (no regression vs. before this Dockerfile even touched apk).
USER root
RUN apk add --no-cache --upgrade libssl3=3.5.8-r0 libcrypto3=3.5.8-r0
USER 101

# --chmod: the non-root nginx user (uid 101) must read the config regardless of
# the host file mode (Write may create it 0640). The site tree from the build
# stage is already world-readable (dirs 0755 / files 0644) so it needs no chmod
# (a blanket --chmod=0644 would strip dir traversal → 403).
COPY --chmod=0644 docs-site/nginx.conf /etc/nginx/conf.d/default.conf
# participant root (brief only):
COPY --from=build /site /usr/share/nginx/html
# 運営 root (想定解・解説込み) — gated at the ingress by /check-admin:
COPY --from=build /site-admin /usr/share/nginx/html-admin
EXPOSE 8080
