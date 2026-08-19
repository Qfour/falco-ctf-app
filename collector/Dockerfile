# collector — Go service (participant-facing front, P11.5). Build context = repo root.
#   docker build -f collector/Dockerfile -t <registry>/collector:<tag> .
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS build
WORKDIR /src

# Copy module files first for layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/collector ./cmd/collector
COPY internal/collector ./internal/collector
COPY internal/serverutil ./internal/serverutil
# The collector reuses the scoreboard's httpx + ratelimit helpers (no fork).
COPY internal/scoreboard/httpx ./internal/scoreboard/httpx
COPY internal/scoreboard/ratelimit ./internal/scoreboard/ratelimit
# Only route.go (Route/Register, stdlib-only) — NOT the whole internal/apispec
# directory, which also holds internal/apispec/specparity (yaml.v3-dependent
# spec-loading/parity-comparison code, imported ONLY from *_test.go files).
# BLOCKING 1 (5x review): this service failed to build at all before this
# line existed (internal/collector/collector.go imports internal/apispec for
# Route/Register), and the fix is this single-file COPY, not the whole
# directory — copying the directory would still build (extra unimported
# files on disk are harmless to `go build ./cmd/collector`), but copying only
# the thin file keeps the build context itself honest about what this
# distroless binary actually needs.
COPY internal/apispec/route.go ./internal/apispec/route.go

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/collector ./cmd/collector

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
COPY --from=build --chown=65532:65532 /out/collector /app/collector
EXPOSE 8000
ENTRYPOINT ["/app/collector"]
