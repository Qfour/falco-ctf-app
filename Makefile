# falco-ctf-app — application-side build / dev / deploy targets.
#
# Conventions:
#   REGISTRY/TAG control image naming. TAG defaults to the current git SHA.
#   For local k8s deploy with the overlay (newTag: dev): make build TAG=dev && make deploy-local
#   For local CVE scan: make scan TAG=local (builds first automatically)

REGISTRY     ?= docker.io/falco-ctf
TAG          ?= $(shell git rev-parse --short HEAD)
IMAGES       := scoreboard auth-policy ttyd challenge
SYSDIG_URL   ?= https://app.au1.sysdig.com

# Go toolchain runs inside Docker (no local Go required). `test` uses
# `docker build` so it works under Colima too, where bind mounts of the
# host repo are not shared into the VM.
GO_IMAGE ?= golang:1.25-alpine

.PHONY: help dev dev-down build push load-colima deploy-local lint test tidy gen clean scan

help:
	@echo "Targets:"
	@echo "  dev           — docker compose up (scoreboard hot-reload on http://localhost:8000)"
	@echo "  dev-down      — docker compose down"
	@echo "  build         — docker build all images ($(REGISTRY)/<name>:$(TAG))"
	@echo "  push          — docker push all images"
	@echo "  load-colima   — load images into colima k3s containerd (local only)"
	@echo "  deploy-local  — kubectl apply -k deploy/<app>/overlays/local"
	@echo "  lint          — kustomize build all overlays (validate Kustomize)"
	@echo "  test          — go test ./... (runs in $(GO_IMAGE) container)"
	@echo "  tidy          — go mod tidy (runs in $(GO_IMAGE) container)"
	@echo "  gen           — regenerate Go types from OpenAPI specs (docs/openapi-*.yaml)"
	@echo "  scan          — sysdig-cli-scanner on all built images (SYSDIG_SECURE_API_TOKEN required)"
	@echo "  clean         — remove built images locally"

dev:
	docker compose up --build

dev-down:
	docker compose down

build:
	docker build -t $(REGISTRY)/scoreboard:$(TAG)  -f scoreboard/Dockerfile  .
	docker build -t $(REGISTRY)/auth-policy:$(TAG) -f auth-policy/Dockerfile .
	docker build -t $(REGISTRY)/ttyd:$(TAG)        -f images/ttyd/Dockerfile      images/ttyd
	docker build -t $(REGISTRY)/challenge:$(TAG)   -f images/challenge/Dockerfile .

push:
	@for img in $(IMAGES); do docker push $(REGISTRY)/$$img:$(TAG); done

load-colima: build
	./scripts/build-and-load.sh

deploy-local:
	kubectl apply -k deploy/scoreboard/overlays/local
	kubectl apply -k deploy/auth-policy/overlays/local

lint:
	@for d in deploy/*/overlays/*; do echo "== $$d =="; kubectl kustomize $$d >/dev/null; done

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
