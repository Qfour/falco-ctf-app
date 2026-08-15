# scoreboard — Go service. Build context = repo root.
#   docker build -f scoreboard/Dockerfile -t <registry>/scoreboard:<tag> .
#
# The challenges/ catalog + scenarios/ manifests are baked into the image
# (read at startup; scenarios/ selects an event composition via SCENARIO_FILE).
# Local dev overlays challenges/ via a volume mount in docker-compose.yml.
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS build
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
