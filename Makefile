# falco-ctf-app — application-side build / dev / deploy targets.
#
# Conventions:
#   REGISTRY/TAG control image naming. TAG defaults to the current git SHA.
#   For local k8s deploy: make load-colima then `helmfile -e local apply` in
#   falco-ctf-platform (canonical). `make deploy-local` installs just the two
#   app charts for app-only iteration.
#   For local CVE scan: make scan TAG=local (builds first automatically)

REGISTRY     ?= docker.io/falco-ctf
TAG          ?= $(shell git rev-parse --short HEAD)
IMAGES       := scoreboard auth-policy ttyd challenge docs
SYSDIG_URL   ?= https://app.au1.sysdig.com

# Go toolchain runs inside Docker (no local Go required). `test` uses
# `docker build` so it works under Colima too, where bind mounts of the
# host repo are not shared into the VM.
GO_IMAGE ?= golang:1.26-alpine

.PHONY: help dev dev-down build push load-colima deploy-local lint test tidy gen gen-values check-flags check-rules check-freshness clean scan

help:
	@echo "Targets:"
	@echo "  dev             — docker compose up (scoreboard hot-reload on http://localhost:8000)"
	@echo "  dev-down        — docker compose down"
	@echo "  build           — docker build all images ($(REGISTRY)/<name>:$(TAG))"
	@echo "  push            — docker push all images"
	@echo "  load-colima     — load images into colima k3s containerd (local only)"
	@echo "  deploy-local    — helm upgrade --install scoreboard + auth-policy charts (local)"
	@echo "  lint            — helm lint all charts/"
	@echo "  test            — go test ./... (runs in $(GO_IMAGE) container)"
	@echo "  tidy            — go mod tidy (runs in $(GO_IMAGE) container)"
	@echo "  gen             — regenerate Go types from OpenAPI specs (docs/openapi-*.yaml)"
	@echo "  gen-values      — regenerate challenge values.yaml / values-all.yaml from plant.sh"
	@echo "  check-flags     — fail if real flags leak into tracked files or values are stale"
	@echo "  check-rules     — fail if a challenge references a non-existent Falco rule"
	@echo "  check-freshness — fail if a Dockerfile base image cycle is past EOL (needs network)"
	@echo "  scan            — sysdig-cli-scanner on all built images (SYSDIG_SECURE_API_TOKEN required)"
	@echo "  clean           — remove built images locally"

dev:
	docker compose up --build

dev-down:
	docker compose down

build:
	docker build -t $(REGISTRY)/scoreboard:$(TAG)  -f scoreboard/Dockerfile  .
	docker build -t $(REGISTRY)/auth-policy:$(TAG) -f auth-policy/Dockerfile .
	docker build -t $(REGISTRY)/ttyd:$(TAG)        -f images/ttyd/Dockerfile      images/ttyd
	docker build -t $(REGISTRY)/challenge:$(TAG)   -f images/challenge/Dockerfile .
	docker build -t $(REGISTRY)/docs:$(TAG)        -f images/docs/Dockerfile        .

push:
	@for img in $(IMAGES); do docker push $(REGISTRY)/$$img:$(TAG); done

load-colima: build
	./scripts/build-and-load.sh

# App-only cluster iteration. The full local stack (ingress / dex / oauth2-proxy
# / falco) comes from falco-ctf-platform `helmfile -e local apply`; this installs
# just the two app charts with local-equivalent values (images tagged :dev via
# make load-colima). Namespaces are created by the charts.
deploy-local:
	helm upgrade --install scoreboard charts/scoreboard -n scoreboard \
	  --set image.tag=dev \
	  --set persistence.storageClassName=local-path \
	  --set ingress.host=scoreboard.192.168.64.2.nip.io --set ingress.tls=true \
	  --set ingress.authSignin='http://auth.192.168.64.2.nip.io/oauth2/start?rd=$$scheme://$$host$$escaped_request_uri'
	helm upgrade --install auth-policy charts/auth-policy -n auth-policy \
	  --set image.tag=dev \
	  --set env.expectedEmailDomain=ctf.local --set env.adminEmails=user1@ctf.local

lint:
	@for c in charts/*; do echo "== $$c =="; helm lint "$$c"; done

test:
	docker build -f Dockerfile.test --progress=plain -t falco-ctf/gotest:local .

# Uses a `docker build -o .` export stage so it works under Colima (which
# does not share the host repo path into its VM by default).
tidy:
	docker build -f Dockerfile.tidy --target export -o . .

# Re-generates internal/*/oapi/types.gen.go from docs/openapi-*.yaml.
# Commit the result; CI diff-check will catch spec/code drift.
gen:
	docker build -f Dockerfile.gen --target export -o . .

gen-values:
	./challenges/gen-values.sh

check-flags:
	./scripts/check-flags.sh

check-rules:
	./scripts/check-challenge-rules.sh

check-freshness:
	./scripts/check-freshness.sh

scan: build
	@command -v sysdig-cli-scanner >/dev/null 2>&1 || \
	  { echo "error: sysdig-cli-scanner not found — install from https://docs.sysdig.com/en/docs/sysdig-secure/vulnerabilities/pipeline/"; exit 1; }
	@[ -n "$$SYSDIG_SECURE_API_TOKEN" ] || \
	  { echo "error: SYSDIG_SECURE_API_TOKEN is not set"; exit 1; }
	@SCAN_FAIL=0; for img in $(IMAGES); do \
	  echo "==> scanning $(REGISTRY)/$$img:$(TAG)"; \
	  sysdig-cli-scanner --apiurl $(SYSDIG_URL) $(REGISTRY)/$$img:$(TAG) || SCAN_FAIL=1; \
	done; exit $$SCAN_FAIL

clean:
	@for img in $(IMAGES); do docker rmi -f $(REGISTRY)/$$img:$(TAG) 2>/dev/null || true; done
