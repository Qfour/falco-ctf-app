# falco-ctf-app — application-side build / dev / deploy targets.
#
# Conventions:
#   REGISTRY/TAG control image naming. Defaults match the platform repo's
#   charts/ctf-user values and deploy/*/overlays/local kustomization.
#   Override for CI: `make build REGISTRY=ghcr.io/sysdig TAG=$(git rev-parse --short HEAD)`.

REGISTRY ?= docker.io/falco-ctf
TAG      ?= dev
IMAGES   := scoreboard auth-policy ttyd challenge

.PHONY: help dev dev-down build push load-colima deploy-local lint test clean

help:
	@echo "Targets:"
	@echo "  dev           — docker compose up (scoreboard hot-reload on http://localhost:8000)"
	@echo "  dev-down      — docker compose down"
	@echo "  build         — docker build all images ($(REGISTRY)/<name>:$(TAG))"
	@echo "  push          — docker push all images"
	@echo "  load-colima   — load images into colima k3s containerd (local only)"
	@echo "  deploy-local  — kubectl apply -k deploy/<app>/overlays/local"
	@echo "  lint          — kustomize build all overlays (validate Kustomize)"
	@echo "  clean         — remove built images locally"

dev:
	docker compose up --build

dev-down:
	docker compose down

build:
	docker build -t $(REGISTRY)/scoreboard:$(TAG)  -f scoreboard/Dockerfile  .
	docker build -t $(REGISTRY)/auth-policy:$(TAG) -f auth-policy/Dockerfile .
	docker build -t $(REGISTRY)/ttyd:$(TAG)        -f images/ttyd/Dockerfile      images/ttyd
	docker build -t $(REGISTRY)/challenge:$(TAG)   -f images/challenge/Dockerfile images/challenge

push:
	@for img in $(IMAGES); do docker push $(REGISTRY)/$$img:$(TAG); done

load-colima: build
	./scripts/build-and-load.sh

deploy-local:
	kubectl apply -k deploy/scoreboard/overlays/local
	kubectl apply -k deploy/auth-policy/overlays/local

lint:
	@for d in deploy/*/overlays/*; do echo "== $$d =="; kubectl kustomize $$d >/dev/null; done

clean:
	@for img in $(IMAGES); do docker rmi -f $(REGISTRY)/$$img:$(TAG) 2>/dev/null || true; done
