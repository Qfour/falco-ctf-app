# collector — Go service (participant-facing front, P11.5). Build context = repo root.
#   docker build -f collector/Dockerfile -t <registry>/collector:<tag> .
FROM golang:1.26-alpine AS build
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

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/collector ./cmd/collector

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build --chown=65532:65532 /out/collector /app/collector
EXPOSE 8000
ENTRYPOINT ["/app/collector"]
