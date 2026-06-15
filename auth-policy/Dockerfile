# auth-policy — Go service. Build context = repo root.
#   docker build -f auth-policy/Dockerfile -t <registry>/auth-policy:<tag> .
FROM golang:1.25-alpine AS build
WORKDIR /src

# Copy module files first for layer caching. `go.su[m]` is a glob that
# silently no-ops when go.sum doesn't exist yet (auth-policy has no
# external deps, so go.sum may be absent until scoreboard lands).
COPY go.mod ./
COPY go.su[m] ./
RUN go mod download

COPY cmd/auth-policy ./cmd/auth-policy
COPY internal/authpolicy ./internal/authpolicy
COPY internal/serverutil ./internal/serverutil

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/auth-policy ./cmd/auth-policy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --chown=65532:65532 /out/auth-policy /app/auth-policy
EXPOSE 8000
ENTRYPOINT ["/app/auth-policy"]
