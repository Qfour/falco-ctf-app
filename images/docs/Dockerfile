# docs site image — MkDocs Material (participant + 運営 builds), served by nginx.
#
# Build context: **repo root** (so the canonical `challenges/` tree is reachable;
# gen-pages.py renders one page per challenge from it — no committed duplication).
#   docker build --platform linux/amd64 -t <reg>/docs:<tag> -f images/docs/Dockerfile .
FROM python:3.12-slim AS build

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
FROM nginxinc/nginx-unprivileged:1.27-alpine
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
