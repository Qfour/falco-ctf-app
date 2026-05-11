# auth-policy — Go service. Build context = repo root.
#   docker build -f auth-policy/Dockerfile -t <registry>/auth-policy:<tag> .
FROM golang:1.23-alpine AS build
WORKDIR /src

# Copy module files first for layer caching. `go.su[m]` is a glob that
# silently no-ops when go.sum doesn't exist yet (auth-policy has no
# external deps, so go.sum may be absent until scoreboard lands).
COPY go.mod ./
COPY go.su[m] ./
RUN go mod download

COPY cmd/auth-policy ./cmd/auth-policy
COPY internal/authpolicy ./internal/authpolicy

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/auth-policy ./cmd/auth-policy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 1000 app
COPY --from=build --chown=1000:1000 /out/auth-policy /app/auth-policy

USER 1000:1000
EXPOSE 8000
ENTRYPOINT ["/app/auth-policy"]
