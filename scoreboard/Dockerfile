# scoreboard — Go service. Build context = repo root.
#   docker build -f scoreboard/Dockerfile -t <registry>/scoreboard:<tag> .
#
# The challenges/ catalog + scenarios/ manifests are baked into the image
# (read at startup; scenarios/ selects an event composition via SCENARIO_FILE).
# Local dev overlays challenges/ via a volume mount in docker-compose.yml.
FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/scoreboard ./cmd/scoreboard
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/scoreboard ./cmd/scoreboard \
 && mkdir -p /out/var/lib/scoreboard

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
COPY --from=build --chown=65532:65532 /out/scoreboard /app/scoreboard
COPY --from=build --chown=65532:65532 /out/var/lib/scoreboard /var/lib/scoreboard
COPY --chown=65532:65532 challenges /app/challenges
COPY --chown=65532:65532 scenarios /app/scenarios

EXPOSE 8000
ENTRYPOINT ["/app/scoreboard"]
