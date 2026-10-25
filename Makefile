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
IMAGES       := scoreboard auth-policy collector ttyd ttyd-proxy challenge docs detect-grader
SYSDIG_URL   ?= https://app.au1.sysdig.com

# Go toolchain runs inside Docker (no local Go required). `test` uses
# `docker build` so it works under Colima too, where bind mounts of the
# host repo are not shared into the VM.
GO_IMAGE ?= golang:1.26-alpine

.PHONY: help dev dev-down build push load-colima deploy-local helm-dep-build lint check-seccomp check-flag-isolation check-namespace-ownership check-image-hygiene check-image-hygiene-selftest test e2e e2e-serve check-e2e-verdict tidy gen gen-home-fragments gen-tutorial-fragments gen-values gen-attack check-flags check-template-hex check-portal-render check-rules check-freshness check-adr check-dockerignore clean scan

help:
	@echo "Targets:"
	@echo "  dev             — docker compose up (scoreboard hot-reload on http://localhost:8000)"
	@echo "  dev-down        — docker compose down"
	@echo "  build           — docker build all images ($(REGISTRY)/<name>:$(TAG))"
	@echo "  push            — docker push all images"
	@echo "  load-colima     — load images into colima k3s containerd (local only)"
	@echo "  deploy-local    — helm upgrade --install scoreboard + auth-policy charts (local)"
	@echo "  helm-dep-build      — helm dependency build for every chart that declares one (P21 item 5: falco-ctf-common)"
	@echo "  lint                — helm-dep-build + helm lint all charts/ + check-seccomp + check-flag-isolation + check-namespace-ownership"
	@echo "  check-seccomp       — fail if any rendered chart container's effective seccompProfile != RuntimeDefault"
	@echo "  check-flag-isolation — fail if the ctf-user chart lets a flag reach the challenge container (ADR-0001 Verification 1)"
	@echo "  check-namespace-ownership — fail if any chart (except ctf-user) renders its own kind: Namespace (ADR-0011)"
	@echo "  check-image-hygiene — fail if the built challenge image's /opt/ctf/plant-seed/ snapshot carries flag/hash material or drifts from its real counterpart (ADR-0001 Verification 2-8), or if /opt/ctf/missions is not exactly <id>/fixtures/** (ADR-0026 V1-V3)"
	@echo "  check-image-hygiene-selftest — mutation test: derived images with one deliberate violation each must FAIL check-image-hygiene (ADR-0026 V6)"
	@echo "  test            — go test ./... (runs in $(GO_IMAGE) container)"
	@echo "  e2e             — browser E2E (ADR-0031): real scoreboard + real Chromium in Dockerfile.e2e; verdict made on the host, needs python3 (advisory CI job: e2e)"
	@echo "  e2e-serve       — SEED=<name> [AS=user1] [E2E_PORT=8787]: seeded portal with injected identity on 127.0.0.1 only (ADR-0031 D1 (a))"
	@echo "  check-e2e-verdict — planted-defect fixtures for the e2e verdict (ADR-0031 V6)"
	@echo "  tidy            — go mod tidy (runs in $(GO_IMAGE) container)"
	@echo "  gen             — regenerate Go types from OpenAPI specs (docs/openapi-*.yaml)"
	@echo "  gen-home-fragments — regenerate Portal Home tab HTML fragments (docs-site/home-fragments.yaml)"
	@echo "  gen-tutorial-fragments — regenerate Portal Tutorial tab HTML fragments (docs-site/tutorial-chapters.yaml)"
	@echo "  gen-values      — regenerate challenge values.yaml / values-all.yaml / values-scenario-<name>.yaml from plant.sh + scenarios/"
	@echo "  gen-attack      — regenerate ATT&CK Navigator layer + coverage table from falco-rule.yaml attack: blocks"
	@echo "  check-flags     — fail if real flags leak into tracked files or values are stale; + deploy-user.sh --flags-file validation tests + deploy-time missions allowlist (ADR-0026 V4, 3-8) selftest; + deploy-user.sh seat-grammar check against the shared case table (app#480); + fail on any tracked email outside the reserved domains (ADR-0034 V17)"
	@echo "  check-template-hex — fail if a raw hex color literal appears under view/templates/ (recursive: index.html + portal/*.tmpl; app#116 — single design-token source is static/tokens.css)"
	@echo "  check-portal-render — (macOS, optional; not in CI) run the portal evade-card render functions under jsc and assert ADR-0027 D6 (no clean claim for a non-current evade; dirty always shown; escaping)"
	@echo "  check-rules     — fail if a challenge references a non-existent Falco rule"
	@echo "  check-freshness — fail if a Dockerfile base image cycle is past EOL (needs network)"
	@echo "  check-dockerignore — fail if .dockerignore stops excluding decrypted/credential files (*.dec.yaml, *.dec.json, kubeconfig*, *.secret.*) or a tracked file matches them (app#322)"
	@echo "  check-adr       — fail on ADR number collisions, filename/header drift, or docs/adr/README.md index gaps (#181); prints the next free ADR number on success"
	@echo "  scan            — sysdig-cli-scanner on all built images (SYSDIG_SECURE_API_TOKEN required)"
	@echo "  clean           — remove built images locally"

dev:
	docker compose up --build

dev-down:
	docker compose down

build:
	docker build -t $(REGISTRY)/scoreboard:$(TAG)  -f scoreboard/Dockerfile  .
	docker build -t $(REGISTRY)/auth-policy:$(TAG) -f auth-policy/Dockerfile .
	docker build -t $(REGISTRY)/collector:$(TAG)   -f collector/Dockerfile   .
	docker build -t $(REGISTRY)/ttyd:$(TAG)        -f images/ttyd/Dockerfile      images/ttyd
	docker build -t $(REGISTRY)/ttyd-proxy:$(TAG)  -f images/ttyd-proxy/Dockerfile .
	docker build -t $(REGISTRY)/challenge:$(TAG)   -f images/challenge/Dockerfile .
	docker build -t $(REGISTRY)/docs:$(TAG)        -f images/docs/Dockerfile        .
	docker build -t $(REGISTRY)/detect-grader:$(TAG) -f images/detect-grader/Dockerfile images/detect-grader
	$(MAKE) check-image-hygiene

# check-image-hygiene first: prod is CI-free and an operator runs `make push` by
# hand, so an image that was never through V1-V3 (e.g. `make build` failed) must
# not be pushable (ADR-0026). It checks the challenge image about to be pushed.
push: check-image-hygiene
	@for img in $(IMAGES); do docker push $(REGISTRY)/$$img:$(TAG); done

load-colima: build
	./scripts/build-and-load.sh

# App-only cluster iteration. The full local stack (ingress / dex / oauth2-proxy
# / falco) comes from falco-ctf-platform `helmfile -e local apply`; this installs
# just the two app charts with local-equivalent values (images tagged :dev via
# make load-colima). Namespaces are created by the charts.
deploy-local: helm-dep-build
	helm upgrade --install scoreboard charts/scoreboard -n scoreboard \
	  --set image.tag=dev \
	  --set env.expectedEmailDomain=ctf.local \
	  --set persistence.storageClassName=local-path \
	  --set ingress.host=scoreboard.192.168.64.2.nip.io --set ingress.tls=true \
	  --set ingress.authSignin='http://auth.192.168.64.2.nip.io/oauth2/start?rd=$$scheme://$$host$$escaped_request_uri'
	@# ADR-0034 D2: auth-policy refuses to start without a roster, so the dev
	@# roster Secret (key roster.yaml) must exist before the pod. The dev admin
	@# must NOT be a roster seat's canonical email (startup error), hence
	@# admin@ctf.local and not user1@ctf.local.
	kubectl -n auth-policy create secret generic auth-policy-roster \
	  --from-file=roster.yaml=scripts/dev-roster.yaml --dry-run=client -o yaml | kubectl apply -f -
	helm upgrade --install auth-policy charts/auth-policy -n auth-policy \
	  --set image.tag=dev \
	  --set env.expectedEmailDomain=ctf.local --set env.adminEmails=admin@ctf.local

# P21 item 5 (REFACTORING.md): charts/{scoreboard,auth-policy,collector,docs,
# ctf-user} pull in the charts/falco-ctf-common library chart
# (securityContext / default-deny NetworkPolicy / labels / image named
# templates — step1 landed the first two, step2 added labels+image and
# onboarded docs+ctf-user) via a local `file://../falco-ctf-common`
# dependency in their Chart.yaml. Helm resolves file:// dependencies onto disk
# (charts/<chart>/charts/falco-ctf-common-*.tgz + Chart.lock) — this is a NEW
# step in the local dev loop: without it, `helm lint`/`helm template`/`helm
# upgrade` on any of those five charts fails with "found in Chart.yaml, but
# missing in charts/ directory". The only chart with no `dependencies:` key
# is falco-ctf-common itself — the loop below is a harmless no-op for it.
# Safe to re-run; only touches the gitignored charts/<chart>/charts/ vendor
# dirs + Chart.lock.
helm-dep-build:
	@for c in charts/*; do \
	  if grep -q '^dependencies:' "$$c/Chart.yaml" 2>/dev/null; then \
	    echo "== helm dependency build $$c =="; \
	    helm dependency build "$$c"; \
	  fi \
	done

lint: helm-dep-build check-seccomp check-flag-isolation check-namespace-ownership
	@for c in charts/*; do echo "== $$c =="; helm lint "$$c"; done

# Hard Invariant guard (see .claude/rules/falco-ctf-app-conventions.md
# "SecurityContext"): every rendered chart's containers must have an
# effective seccompProfile.type of RuntimeDefault. helm lint/template alone
# don't inspect content, so without this a Pod-level seccompProfile
# regression (e.g. charts/ctf-user/templates/pod.yaml) would go undetected.
check-seccomp:
	python3 scripts/check-seccomp.py

# ADR-0001 (Option B) Verification 1: allowlist-type static assert that no
# flag ever reaches the `challenge` container (env/envFrom/volumeMount/Role)
# across every render-matrix scope. See scripts/check-flag-isolation.sh.
check-flag-isolation:
	./scripts/check-flag-isolation.sh

# ADR-0011 follow-up (platform#111): fail if any chart (except ctf-user,
# which the ADR explicitly excludes) renders its own kind: Namespace object.
# Namespace ownership for auth-policy/collector/scoreboard/docs is now the
# sole responsibility of platform's `namespaces` bootstrap release — see
# scripts/check-namespace-ownership.sh and docs/adr/0011-namespace-bootstrap-single-owner.md.
check-namespace-ownership:
	./scripts/check-namespace-ownership.sh

# ADR-0001 Verification 2-8 / DoD 15: re-verify the challenge image's
# /opt/ctf/plant-seed/ build-time snapshot at every build (fail-closed —
# prod is CI-free, so `build` is the only gate that always runs; see
# scripts/check-image-hygiene.sh for why this can't live in CI alone).
check-image-hygiene:
	./scripts/check-image-hygiene.sh $(REGISTRY)/challenge:$(TAG)

# ADR-0026 V6: proves check-image-hygiene.sh can actually fail (23 cases:
# derived images with one deliberate violation each, plus build-context cases).
# Not part of `make build` (it builds extra throwaway images); CI's image-hygiene
# job runs it after the check. It TEMPORARILY EDITS challenges/ and restores it
# with `git checkout`: never run it on a tree with uncommitted changes under
# challenges/, and never in parallel with another run.
check-image-hygiene-selftest:
	./scripts/test-check-image-hygiene.sh $(REGISTRY)/challenge:$(TAG)

test:
	docker build -f Dockerfile.test --progress=plain -t falco-ctf/gotest:local .

# Browser E2E (ADR-0031). Not part of `make test`: that only COMPILES the
# e2e-tagged code (`go vet -tags e2e`). The scenarios run inside a BuildKit RUN
# with no network; BuildKit exports nothing from a failed RUN, so the run script
# always exits 0 and leaves `go test -json` + its exit code in the export dir, and
# scripts/e2e-verdict.py judges them HERE, fail-closed: exit code, this run's id and
# SHA (a stale or cached verdict is refused; "<sha>-dirty" when the work tree has
# uncommitted changes, since the build context is the tree), no skip, and the set of passed tests
# equal to internal/e2e/expected_tests.txt. E2E_OUT is fixed (it is rm -rf'd):
# `override` makes the assignment win over `make e2e E2E_OUT=...` and over an
# E2E_OUT in the environment (under `make -e`), which a plain `:=` does not.
override E2E_OUT := .e2e-out
e2e:
	rm -rf $(E2E_OUT)
	mkdir -p $(E2E_OUT)
	@run_id="$$(date +%s)-$$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; \
	sha="$$(git rev-parse HEAD)"; \
	if [ -n "$$(git status --porcelain)" ]; then sha="$$sha-dirty"; echo "warning: uncommitted changes — the verdict is for the work tree, not for HEAD" >&2; fi; \
	echo "== make e2e: run $$run_id, HEAD $$sha =="; \
	docker build -f Dockerfile.e2e --target export --progress=plain \
	  --build-arg E2E_RUN_ID="$$run_id" --build-arg E2E_GIT_SHA="$$sha" \
	  -o $(E2E_OUT) . || exit 1; \
	python3 scripts/e2e-verdict.py --dir $(E2E_OUT) --expected internal/e2e/expected_tests.txt \
	  --run-id "$$run_id" --sha "$$sha"

# The same child + proxy + seed as `make e2e`, for a person (or Claude in
# Chrome) to look at. The one published port is bound to the host's loopback
# (-p 127.0.0.1:...), and the container is read-only, capability-less and
# non-root. The charset checks on SEED / AS below are an early, readable error,
# not a boundary (make expands the values into the recipe before any shell sees
# them); the boundary is the e2e-serve binary, which validates SEED, AS
# (harness.EmailFor) and E2E_PORT again. Until ADR-0031 stage P is complete
# (D1 (a) (i)-(v)), only a person opens this — not Claude in Chrome.
E2E_PORT ?= 8787
# AS is make's built-in name for the assembler (default "as"), so `?=` would keep
# that: take it from the command line only, else user1.
E2E_USER := $(if $(filter command line,$(origin AS)),$(AS),user1)
e2e-serve:
	@case "$(SEED)" in ''|*[!a-z0-9-]*|-*) echo "error: SEED=<name> is required ([a-z0-9-]); see internal/e2e/harness/seed.go (fresh, clean-05, dirty-05)" >&2; exit 2;; esac
	@case "$(E2E_USER)" in ''|*[!a-z0-9-]*|-*|*-|??????????????????????????????????????????????????????*) echo "error: AS must match ^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$$ (a seat: 1 to 53 characters, ending in a letter or digit)" >&2; exit 2;; esac
	@case "$(E2E_PORT)" in ''|*[!0-9]*) echo "error: E2E_PORT must be a number >= 1024" >&2; exit 2;; esac
	docker build -f Dockerfile.e2e --target serve -t falco-ctf/e2e-serve:local .
	docker run --rm --name falco-ctf-e2e-serve \
	  -p 127.0.0.1:$(E2E_PORT):$(E2E_PORT) \
	  --read-only --tmpfs /tmp:rw,mode=1777 --cap-drop ALL --security-opt no-new-privileges \
	  -e SEED=$(SEED) -e AS=$(E2E_USER) -e E2E_PORT=$(E2E_PORT) \
	  falco-ctf/e2e-serve:local

check-e2e-verdict:
	./scripts/check-e2e-verdict.sh

# Uses a `docker build -o .` export stage so it works under Colima (which
# does not share the host repo path into its VM by default).
tidy:
	docker build -f Dockerfile.tidy --target export -o . .

# Re-generates internal/*/oapi/types.gen.go from docs/openapi-*.yaml.
# Commit the result; CI diff-check will catch spec/code drift.
gen:
	docker build -f Dockerfile.gen --target export -o . .

# Regenerates internal/scoreboard/view/homefragments_gen.go from docs-site/docs/*.md
# + challenges/<NN>-<slug>/rule-explain.md, per docs-site/home-fragments.yaml
# (content-lead's contract). Commit the result.
gen-home-fragments:
	docker build -f Dockerfile.gen-home-fragments --target export -o . .

# Regenerates internal/scoreboard/view/tutorialfragments_gen.go from
# docs-site/docs/{index,cheatsheet}.md + docs-site/tutorial/*.md, per
# docs-site/tutorial-chapters.yaml (content-lead's contract, P24). Commit
# the result.
gen-tutorial-fragments:
	docker build -f Dockerfile.gen-tutorial-fragments --target export -o . .

gen-values:
	./challenges/gen-values.sh

# Regenerates challenges/attack-navigator-layer.json + challenges/ATTACK-COVERAGE.md
# from the attack: blocks in challenges/*/falco-rule.yaml (single source). Idempotent.
gen-attack:
	python3 scripts/gen-attack-layer.py

check-flags:
	./scripts/check-flags.sh
	./scripts/check-flags-file-validation.sh
	./scripts/check-seat-grammar.sh
	./scripts/check-missions-allowlist-assert.sh
	./scripts/check-emails.sh
	./scripts/check-emails-selftest.sh

check-template-hex:
	./scripts/check-template-hex.sh

# jsc (JavaScriptCore) ships with macOS; not part of `make test` / CI.
check-portal-render:
	./scripts/check-portal-render.sh

check-rules:
	./scripts/check-challenge-rules.sh

check-freshness:
	./scripts/check-freshness.sh

check-adr:
	./scripts/check-adr-numbers.sh

# app#322 (ADR-0031 H1 (h)): .dockerignore must keep excluding decrypted /
# credential files from every build context. --selftest proves the guard
# rejects broken inputs. See scripts/check-dockerignore.sh.
check-dockerignore:
	./scripts/check-dockerignore.sh
	./scripts/check-dockerignore.sh --selftest

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
