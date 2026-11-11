# ttyd-proxy — Go service (P23-3). Sits in front of ttyd inside the ctf-user
# workspace Pod and stamps Content-Security-Policy: frame-ancestors on every
# response so a malicious page cannot iframe ttyd's writable shell
# (clickjacking mitigation for the P23 unified portal). Build context = repo
# root (shares serverutil with scoreboard/auth-policy/collector).
#   docker build -f images/ttyd-proxy/Dockerfile -t <registry>/ttyd-proxy:<tag> .
FROM golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ttyd-proxy ./cmd/ttyd-proxy
COPY internal/ttydproxy ./internal/ttydproxy
COPY internal/dnsname ./internal/dnsname
COPY internal/serverutil ./internal/serverutil

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/ttyd-proxy ./cmd/ttyd-proxy

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
COPY --from=build --chown=65532:65532 /out/ttyd-proxy /app/ttyd-proxy
EXPOSE 7681
ENTRYPOINT ["/app/ttyd-proxy"]
