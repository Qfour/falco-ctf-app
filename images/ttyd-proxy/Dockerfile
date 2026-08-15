# ttyd-proxy — Go service (P23-3). Sits in front of ttyd inside the ctf-user
# workspace Pod and stamps Content-Security-Policy: frame-ancestors on every
# response so a malicious page cannot iframe ttyd's writable shell
# (clickjacking mitigation for the P23 unified portal). Build context = repo
# root (shares serverutil with scoreboard/auth-policy/collector).
#   docker build -f images/ttyd-proxy/Dockerfile -t <registry>/ttyd-proxy:<tag> .
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ttyd-proxy ./cmd/ttyd-proxy
COPY internal/ttydproxy ./internal/ttydproxy
COPY internal/serverutil ./internal/serverutil

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/ttyd-proxy ./cmd/ttyd-proxy

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
COPY --from=build --chown=65532:65532 /out/ttyd-proxy /app/ttyd-proxy
EXPOSE 7681
ENTRYPOINT ["/app/ttyd-proxy"]
