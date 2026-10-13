# auth-policy — Go service. Build context = repo root.
#   docker build -f auth-policy/Dockerfile -t <registry>/auth-policy:<tag> .
FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src

# Copy module files first for layer caching. This binary has third-party
# dependencies (gopkg.in/yaml.v3 for the roster parser since ADR-0034 S2, and
# the prometheus client for /metrics), so go.sum is required for the build.
# The exact set is pinned by internal/apispec/dependency_boundary_test.go
# (TestAuthPolicyThirdPartyImportsArePinned). The `go.su[m]` glob is a
# leftover from when this service had no external deps and no go.sum; go.sum
# always exists now (a build without it fails at `go mod download`/`go build`).
COPY go.mod ./
COPY go.su[m] ./
RUN go mod download

COPY cmd/auth-policy ./cmd/auth-policy
COPY internal/authpolicy ./internal/authpolicy
COPY internal/identity ./internal/identity
COPY internal/serverutil ./internal/serverutil
# Only route.go (Route/Register, stdlib-only) — NOT the whole internal/apispec
# directory, which also holds internal/apispec/specparity (spec-loading /
# parity-comparison code, imported ONLY from *_test.go files; it is test-only
# code, not part of the roster's yaml.v3 use).
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
# — which "works" by silently pulling the test-only specparity package (and
# any non-stdlib dependency it picks up in the future) into this distroless
# binary's build, reopening BLOCKING 1 above. (gopkg.in/yaml.v3 is already in
# this binary through internal/authpolicy's roster parser; what widening adds
# is specparity's code, and the set of third-party imports this binary may
# have is pinned separately by TestAuthPolicyThirdPartyImportsArePinned.)
# The correct fix is to move
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
