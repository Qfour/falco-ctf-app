# auth-policy — Go service. Build context = repo root.
#   docker build -f auth-policy/Dockerfile -t <registry>/auth-policy:<tag> .
FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS build
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
# Only route.go (Route/Register, stdlib-only) — NOT the whole internal/apispec
# directory, which also holds internal/apispec/specparity (yaml.v3-dependent
# spec-loading/parity-comparison code, imported ONLY from *_test.go files).
# BLOCKING 1 (5x review): this service failed to build at all before this
# line existed (internal/authpolicy/server.go imports internal/apispec for
# Route/Register), and the fix is this single-file COPY, not the whole
# directory — copying the directory would still build (extra unimported
# files on disk are harmless to `go build ./cmd/auth-policy`), but copying
# only the thin file keeps the build context itself honest about what this
# distroless binary actually needs.
#
# DO NOT widen this COPY to the whole internal/apispec directory to "fix" a
# build error (Requirement 5, final review round). The two build errors this
# line's absence/narrowing can produce both LOOK like they want a wider
# COPY, but do not want one:
#   - if a non-test file in internal/apispec starts importing specparity (or
#     specparity's own code moves into a file this COPY doesn't reach), the
#     build fails with:
#       no required module provides package
#       github.com/Qfour/falco-ctf-app/internal/apispec/specparity; to add
#       it: go get github.com/Qfour/falco-ctf-app/internal/apispec/specparity
#     — a nonsensical suggestion for a package that already lives in this
#     SAME module; `go get` cannot fix a missing COPY.
#   - if route.go itself is split so part of what it needs lives in another
#     internal/apispec file this COPY doesn't reach, the build fails with a
#     PHANTOM compile error shaped like `undefined: apispec.<Name>` — green
#     on the host (where the whole directory exists) and red ONLY inside
#     this image build.
# Either error's "obvious" fix is `COPY internal/apispec ./internal/apispec`
# — which "works" by silently pulling specparity's yaml.v3 dependency (and
# any future non-stdlib dependency specparity picks up) into this distroless
# binary's build, reopening BLOCKING 1 above. The correct fix is to move
# whatever code triggered the error into internal/apispec/specparity (or a
# *_test.go file) instead of widening this line.
# internal/apispec/dependency_boundary_test.go's TestNoProductionBinaryImportsSpecparity
# / TestInternalApispecIsStdlibOnly assert this invariant at `make test` —
# not image-build — time, which is the actually-required check
# (`gen-diff-check` and `build (collector) / scan` are not required checks;
# falco-api skill / scripts/change-mgmt/setup-rulesets.sh).
COPY internal/apispec/route.go ./internal/apispec/route.go

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w" -trimpath \
      -o /out/auth-policy ./cmd/auth-policy

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d29e660cc75a5b6b1334e03c5c81ccf9bc0884a002c6000dbf0fb96034814478
COPY --from=build --chown=65532:65532 /out/auth-policy /app/auth-policy
EXPOSE 8000
ENTRYPOINT ["/app/auth-policy"]
