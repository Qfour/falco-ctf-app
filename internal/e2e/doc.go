// Package e2e is the browser E2E harness of ADR-0031: Go tests that start the
// real cmd/scoreboard binary as a child process, put a recording reverse proxy
// in front of it, and drive a real headless Chromium (chromedp) against that
// proxy. It is run by `make e2e` (Dockerfile.e2e), never by `make test`.
//
// This file is the only one in the package without the `e2e` build tag. It
// exists so that `go vet ./...` and `go build ./...` see a buildable package
// (every other file needs `-tags e2e`: `go vet -tags e2e ./...` in
// Dockerfile.test compiles them without running them).
//
// Layout:
//
//   - internal/e2e/harness (no build tag, stdlib + yaml only): the proxy, the
//     child-process launcher with its env allowlist, the TLS stub, the HTTP
//     seeds and the Chromium flag allowlist. It has no chromedp import, so its
//     unit tests run in `make test` (required), not only in `make e2e`.
//   - internal/e2e (this package, `e2e` tag): the chromedp helper, the common
//     assertions, the scenarios (E3) and the self-test of the assertions (V2).
//   - internal/e2e/serve: `make e2e-serve`, the same child + proxy + seed for a
//     person (or Claude in Chrome) to look at the portal.
//
// Boundary (ADR-0031 V4): no production binary (cmd/*) may import this tree or
// github.com/chromedp/*; internal/apispec/e2e_boundary_test.go enforces it, and
// allows `//go:build e2e` files only under internal/e2e/.
package e2e
