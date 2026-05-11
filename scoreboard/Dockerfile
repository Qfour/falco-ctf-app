# scoreboard — Go service. Build context = repo root.
#   docker build -f scoreboard/Dockerfile -t <registry>/scoreboard:<tag> .
#
# The challenges/ catalog is baked into the image (Falco-rule files that
# the scoreboard reads at startup). Local dev overlays it via a volume
# mount in docker-compose.yml.
FROM golang:1.23-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/scoreboard ./cmd/scoreboard
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/scoreboard ./cmd/scoreboard

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 1000 app \
 && mkdir -p /var/lib/scoreboard \
 && chown 1000:1000 /var/lib/scoreboard

COPY --from=build --chown=1000:1000 /out/scoreboard /app/scoreboard
COPY --chown=1000:1000 challenges /app/challenges

USER 1000:1000

EXPOSE 8000
ENTRYPOINT ["/app/scoreboard"]
