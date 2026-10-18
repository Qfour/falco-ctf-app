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
# 54874 / 18798 / 14456 / 14457 / 75803 — see Issue #227).
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
#
# The `alpine-slim` variant (app#442, ADR-0036), not `alpine`: docs-site/nginx.conf is
# a static file server (no load_module, no xslt / njs / image-filter / geoip directive),
# and the `alpine` variant adds dynamic modules and curl on top of nginx. Those layers
# pulled libxml2 (xslt), libexpat (fontconfig, via image-filter) and libx11 into the image
# for nothing the site uses, and each new CVE in them was a forced Class-2 bump (#227,
# #339, #436, libx11 / app#471). `apk info -v` of this base (nginx 1.30.6, alpine 3.24.2,
# measured 2026-10-19) is 21 packages: alpine-baselayout(-data), alpine-keys,
# alpine-release, apk-tools / libapk, busybox(-binsh), ca-certificates-bundle,
# gettext-envsubst / libintl, libcrypto3 / libssl3, musl(-utils), nginx, pcre2, scanelf,
# ssl_client, tzdata, zlib. There is NO libexpat, libxml2, libx11, fontconfig, libxslt
# or curl, and /usr/lib/nginx/modules is empty, so nothing is removed here with
# `apk del`, and the HTTP probes (charts/docs/templates/deployment.yaml) do not need curl.
# nginx 1.30.6 — the tag and 1.30.6-alpine-slim resolve to the same index digest
# (`docker buildx imagetools inspect`, 2026-10-19).
FROM nginxinc/nginx-unprivileged:1.30-alpine-slim@sha256:4ac59c85c8c46d9e91eaabd2122cda4923ba380cf11f4138e389f069bcdc77a3

# The one pin that is left (ADR-0036 D2 (b): a package the base already has, raised to
# the fixed build): zlib 1.3.2-r0 in the base, 1.3.2-r1 is what v3.24/main serves
# (`apk policy zlib`, 2026-10-19). libssl3 / libcrypto3 (3.5.9-r0) and pcre2 are at
# the version v3.24/main serves, so they need no pin. Exit condition (D3): drop this
# line when the base digest carries zlib >= 1.3.2-r1.
# apk writes /lib/apk/db as root; the base's Config.User is 101 (non-root), so wrap
# the apk call in USER root / USER 101 and the image still runs as 101.
USER root
RUN apk add --no-cache --upgrade zlib=1.3.2-r1
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
