# docs site image — MkDocs Material site + per-mission PDFs, served by nginx.
#
# Build context: **repo root** (so the canonical `challenges/` tree is reachable;
# gen-pages.sh renders one page per challenge from it — no committed duplication).
#
#   docker build --platform linux/amd64 -t <reg>/docs:<tag> -f images/docs/Dockerfile .
#
# Pages: docs-site/gen-pages.sh -> docs/missions/*.md
# PDFs:  pandoc (weasyprint engine) -> /site/pdf/<NN>.pdf  (CJK via Noto fonts)
FROM python:3.12-slim AS build

# weasyprint runtime libs + pandoc + CJK/emoji fonts for PDF rendering.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pandoc \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
        libffi8 shared-mime-info \
        fonts-noto-cjk fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        "mkdocs-material==9.5.39" \
        "weasyprint==62.3" \
        "pydyf==0.10.0"
        # pydyf pinned: weasyprint 62.x is incompatible with pydyf >=0.11
        # (Stream.transform signature change → 'super' has no attribute 'transform').

WORKDIR /build
COPY challenges/ ./challenges/
COPY docs-site/ ./docs-site/

WORKDIR /build/docs-site
# Build twice from the same source. gen-pages.py decides what each page contains:
#   participant → /site        (brief only — no 想定解/解説, even in the PDF)
#   admin       → /site-admin  (brief + 攻略と解説; 運営専用)
# Site pages (docs/missions) carry time-gated hints (HTML+JS); PDF sources
# (pdfsrc) carry the same hints inline (static), so pandoc renders cleanly.
RUN for mode in participant admin; do \
        out=/site; name="Falco CTF — 課題ドキュメント"; \
        if [ "$mode" = admin ]; then out=/site-admin; name="Falco CTF — 課題ドキュメント (運営用)"; fi; \
        python3 gen-pages.py .. "$mode" \
     && DOCS_SITE_NAME="$name" mkdocs build --strict -d "$out" \
     && mkdir -p "$out/pdf" \
     && for f in pdfsrc/[0-9][0-9]-*.md; do \
            n="$(basename "${f%.md}")"; \
            pandoc "$f" -o "$out/pdf/${n}.pdf" \
                --pdf-engine=weasyprint \
                --resource-path="docs/missions" \
                --metadata title="Falco CTF — ${n}" || exit 1; \
        done \
     && echo "[$mode] $(ls -1 $out/pdf/*.pdf | wc -l) PDFs -> $out"; \
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
