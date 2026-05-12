# scoreboard — Go service. Build context = repo root.
#   docker build -f scoreboard/Dockerfile -t <registry>/scoreboard:<tag> .
#
# The challenges/ catalog is baked into the image (Falco-rule files that
# the scoreboard reads at startup). Local dev overlays it via a volume
# mount in docker-compose.yml.
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/scoreboard ./cmd/scoreboard
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/scoreboard ./cmd/scoreboard \
 && mkdir -p /out/var/lib/scoreboard

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --chown=65532:65532 /out/scoreboard /app/scoreboard
COPY --from=build --chown=65532:65532 /out/var/lib/scoreboard /var/lib/scoreboard
COPY --chown=65532:65532 challenges /app/challenges

EXPOSE 8000
ENTRYPOINT ["/app/scoreboard"]
