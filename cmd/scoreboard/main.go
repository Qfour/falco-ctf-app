// Command scoreboard ingests falcosidekick webhooks, attributes events to
// CTF users via the `ctf-<username>` namespace convention, and serves a
// live dashboard. See internal/scoreboard for the HTTP surface and
// internal/store for persistence guarantees.
package main

import (
	"context"
	"log/slog"
	"os"
	"sync"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/api"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/detect"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/serverutil"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	challengesDir := serverutil.Env("CHALLENGES_DIR", "/app/challenges")
	dbPath := serverutil.Env("SCOREBOARD_DB", "/var/lib/scoreboard/scoreboard.db")
	addr := serverutil.Env("LISTEN_ADDR", ":8000")
	// FLAGS_FILE injects real per-event flags over the FALCO{dev-...}
	// placeholders baked into the public image. Empty = use placeholders.
	flagsFile := serverutil.Env("FLAGS_FILE", "")
	// SCENARIO_FILE restricts scoring + /api/state to one event composition
	// (e.g. the 2-hour killchain subset). Empty = all challenges.
	scenarioFile := serverutil.Env("SCENARIO_FILE", "")
	// ADMIN_EMAILS is the operator allowlist verified against the
	// auth-policy-propagated X-Auth-Request-Email. It gates the admin writes
	// (POST /api/admin/*), the full-event views (GET /api/state and the operator
	// index GET /), and is the self-or-admin exception on the participant
	// self-scope read gate (P18: GET /api/users/{user}/{me,journey} — an admin
	// may read any user, a participant only their own). Empty = nobody
	// (fail-closed everywhere).
	adminEmails := serverutil.SplitCSV(serverutil.Env("ADMIN_EMAILS", ""))
	// ALLOWED_ORIGINS (P23-2) is the CSRF-mitigation allowlist the api
	// handler's origin guard checks every browser-facing state-changing
	// request against (POST /api/admin/*, /api/challenges/{cid}/submit[-detect],
	// /api/users/{user}/... writes — see internal/scoreboard/originguard).
	// Server-to-server routes (POST /internal/exfil/{cid}) are never gated by
	// this, so scoring/ingest is unaffected.
	//
	// Each entry is an exact scheme://host[:port] (no path, no trailing
	// slash). Pre-P19-2b (host-split topology) this held two entries, e.g.
	// "https://scoreboard.example.com,https://journey.example.com". P19-2b
	// (single origin): the admin and journey Ingress objects now share ONE
	// host, so this becomes a SINGLE value, e.g. "https://app.ctf-event.dev"
	// (REFACTORING.md P19-1's confirmed design). NEVER include a
	// `userN.<suffix>` ttyd origin here (security HIGH — see that doc).
	// Empty = every guarded request is DENIED (fail-closed, same posture as
	// ADMIN_EMAILS above): this is a brand-new control, so an operator who has
	// not yet configured it sees loud 403s on every submit/admin POST rather
	// than silently accepting an unvalidated Origin. The platform helmfile MUST
	// set this at deploy time to the real origin (I7: no real domain is
	// hardcoded in this repo). Local dev (docker-compose) sets it to
	// http://localhost:8000 so the bundled dashboard's own admin buttons keep
	// working.
	allowedOrigins := serverutil.SplitCSV(serverutil.Env("ALLOWED_ORIGINS", ""))
	// DOCS_BASE_URL is the origin of the participant docs site (a separate host,
	// e.g. https://docs.<suffix>). When set, the /journey API rewrites each
	// mission's relative docsUrl (/missions/<NN>-<slug>/) into an absolute URL so
	// the link resolves off-origin. Empty = keep the relative path (local dev,
	// where docs are served under the same host or not at all).
	//
	// P23-5: the participant docs Ingress this absolutised URL used to point
	// at has been removed (charts/docs/templates/ingress.yaml) — that
	// content is now in the portal's Home tab (internal/scoreboard/view/
	// home.go). The portal UI no longer renders docsUrl's VALUE into a
	// clickable href (it renders a fixed in-page Home-tab link instead — see
	// templates/portal.html's `docs` var), so DOCS_BASE_URL's absolutisation
	// is currently dead for UI purposes; it is left wired (env,
	// JourneyConfig.DocsBaseURL, api.Handler.docsURL) since docsUrl is still
	// a documented field in the /journey API response
	// (docs/openapi-scoreboard.yaml) and removing it is an API-contract
	// change outside this task's scope. docs-admin (P19-2b: now
	// charts/docs/templates/ingress-admin.yaml at path `/docs-admin` on the
	// single-origin host, not its own subdomain) is UNAFFECTED — this env
	// only ever fed the participant link, never the admin one.
	docsBaseURL := serverutil.Env("DOCS_BASE_URL", "")
	// PORTAL_TTYD_SUFFIX (P23-4) is the DNS suffix the portal's Terminal pane
	// uses to build each caller's OWN ttyd iframe src:
	// `https://<derived-username>.<PORTAL_TTYD_SUFFIX>` (see
	// view.renderPortal / portal.ttydURLFor, and api.DeriveUsername for the
	// username derivation). This MUST equal charts/ctf-user's `dnsSuffix`
	// value (the per-user ttyd Ingress host is `<username>.<dnsSuffix>`
	// there too) or the iframe will 404 / point at the wrong host. Empty
	// (default, and every env before P19 lands) = the Terminal pane renders
	// its fail-safe "not configured" placeholder instead of an iframe —
	// there is no environment-agnostic default to guess (I7), same posture
	// as ALLOWED_ORIGINS/DOCS_BASE_URL above.
	//
	// P19-2b (single origin, confirmed value — REFACTORING.md P19-1): this
	// stays equal to dnsSuffix UNCHANGED (e.g. "ctf-event.dev") — ttyd keeps
	// its OWN per-user subdomain topology (`userN.ctf-event.dev`) even after
	// the portal/dashboard/docs-admin collapse onto a single origin
	// (`app.ctf-event.dev`). Only the FIXED-service host changed; this env's
	// meaning and value are untouched by P19-2b.
	//   - local/PoC (colima): the same "<ip>.nip.io"-style suffix passed to
	//     `deploy-user.sh --dns-suffix` (see charts/ctf-user/deploy-user.sh).
	//   - prod: dnsSuffix (e.g. "ctf-event.dev"). Operators wire this by hand
	//     alongside `deploy-user.sh --dns-suffix` / `--frame-ancestors` (that
	//     script's flag doc covers the companion ttyd-proxy CSP knob P23-3
	//     added, which the single-origin portal host must also be passed to
	//     — see charts/ctf-user/values.yaml ttyd.frameAncestors).
	portalTtydSuffix := serverutil.Env("PORTAL_TTYD_SUFFIX", "")
	// Points policy (#40 self-service hints with a score penalty). PLACEHOLDER
	// defaults — the real per-solve award and per-hint penalty are an event-tuning
	// decision (content-lead / CEO confirm). SCORE_POINTS_PER_SOLVE /
	// SCORE_HINT_PENALTY override at deploy time; a negative penalty is floored to
	// 0 inside the scoring layer (fail-closed: a hint reveal can never raise a
	// score). Empty/unset = the placeholder DefaultPointsPolicy.
	points := scoring.PointsPolicy{
		PerSolve:    serverutil.EnvInt("SCORE_POINTS_PER_SOLVE", scoring.DefaultPointsPerSolve),
		HintPenalty: serverutil.EnvInt("SCORE_HINT_PENALTY", scoring.DefaultHintPenalty),
	}

	cat, err := catalog.Load(challengesDir)
	if err != nil {
		logger.Error("catalog load failed", "dir", challengesDir, "err", err)
		os.Exit(1)
	}
	if err := cat.ApplyFlagOverrides(flagsFile); err != nil {
		logger.Error("flag overrides failed", "file", flagsFile, "err", err)
		os.Exit(1)
	}
	scenarioID := ""
	// order is the mission sequence the Journey UI walks. When a scenario is
	// pinned we honour its explicit challenge order (Restrict returns a map,
	// which loses ordering); otherwise fall back to the catalog's sorted ids
	// (NN- prefixes sort into 01..10 sequence).
	var order []string
	if scenarioFile != "" {
		sc, err := catalog.LoadScenario(scenarioFile)
		if err != nil {
			logger.Error("scenario load failed", "file", scenarioFile, "err", err)
			os.Exit(1)
		}
		if cat, err = cat.Restrict(sc.Challenges); err != nil {
			logger.Error("scenario restrict failed", "scenario", sc.ID, "err", err)
			os.Exit(1)
		}
		scenarioID = sc.ID
		order = sc.Challenges
	} else {
		order = cat.IDs()
	}
	// Journey UI content (title/tagline/briefing/steps/hints/docsUrl). Optional
	// per challenge; a missing journey.yaml just yields no briefing for that
	// mission and the UI degrades gracefully ("ブリーフィング準備中").
	journeys, err := catalog.LoadJourneys(challengesDir, cat)
	if err != nil {
		logger.Error("journey load failed", "dir", challengesDir, "err", err)
		os.Exit(1)
	}
	// Falco rule excerpts (display-only, Story tab's "Falco Rule" panel — P23
	// Story-as-docs). Same source challenges/<NN>-<slug>/rule.yaml the old
	// docs-site has always rendered; fail-soft per challenge (missing file =
	// no panel), loud error on malformed YAML (content mistake, see
	// catalog.LoadRuleExcerpts doc).
	falcoRules, err := catalog.LoadRuleExcerpts(challengesDir, cat)
	if err != nil {
		logger.Error("falco rule excerpt load failed", "dir", challengesDir, "err", err)
		os.Exit(1)
	}
	logger.Info("catalog loaded", "dir", challengesDir, "challenges", cat.IDs(), "journeys", len(journeys), "falco_rule_excerpts", len(falcoRules), "docs_base_url", docsBaseURL, "portal_ttyd_suffix", portalTtydSuffix, "flag_overrides", flagsFile != "", "scenario", scenarioID)

	st, err := store.Open(dbPath)
	if err != nil {
		logger.Error("store open failed", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	logger.Info("store opened", "path", dbPath, "solved_loaded", st.SolvedCount())

	// Detect-challenge grading (type: detect). The scoreboard image is distroless
	// and falco-free (conventions), so grading is delegated to a DetectRunner that
	// runs Falco elsewhere:
	//   - DETECT_RUNNER=k8s    → K8sJob: a per-submission Kubernetes Job in a
	//     dedicated grader namespace (prod). Uses the in-cluster ServiceAccount to
	//     create/watch/delete Jobs; the result is accepted ONLY on a strict
	//     namespace+name(nonce)+labels+succeeded match (never a pod-produced count).
	//     Requires DETECT_GRADER_NAMESPACE + DETECT_GRADER_IMAGE (digest-pinned,
	//     platform-supplied) and the grader RBAC/NetworkPolicy platform provisions
	//     (design §3.1/§3.3/§3.4). Fails closed at boot if in-cluster config or
	//     the required env is missing.
	//   - DETECT_RUNNER=local  → LocalExec: `docker run <DETECT_FALCO_IMAGE>` against
	//     captures on the CHALLENGES_DIR filesystem. For dev / colima / CI only
	//     (needs a docker socket + the challenges dir mounted). NEVER prod.
	//   - DETECT_RUNNER unset/off → feature off (POST /api/challenges/{cid}/submit
	//     -detect returns 503). This is the default so the prod distroless image
	//     does not attempt to grade unless explicitly enabled.
	detectCfg := api.DetectConfig{}
	switch serverutil.Env("DETECT_RUNNER", "off") {
	case "k8s":
		ns := serverutil.Env("DETECT_GRADER_NAMESPACE", "")
		image := serverutil.Env("DETECT_GRADER_IMAGE", "")
		if ns == "" || image == "" {
			logger.Error("detect runner k8s requires DETECT_GRADER_NAMESPACE and DETECT_GRADER_IMAGE", "namespace", ns, "image_set", image != "")
			os.Exit(1)
		}
		jc, err := detect.NewInClusterJobClient()
		if err != nil {
			logger.Error("detect k8s job client init failed (in-cluster config required)", "err", err)
			os.Exit(1)
		}
		detectCfg.Runner = detect.NewK8sJob(cat, ns, image, jc)
		logger.Info("detect runner enabled", "runner", "k8s", "grader_namespace", ns, "grader_image", image)
	case "local":
		falcoImage := serverutil.Env("DETECT_FALCO_IMAGE", "falcosecurity/falco:0.43.1")
		detectCfg.Runner = detect.NewLocalExec(cat, challengesDir, falcoImage)
		logger.Info("detect runner enabled", "runner", "local", "falco_image", falcoImage)
	default:
		logger.Info("detect runner disabled", "hint", "set DETECT_RUNNER=k8s (prod) or =local (dev/colima)")
	}

	handler := scoreboard.NewHandler(cat, st, logger,
		scoreboard.WithDBPath(dbPath),
		scoreboard.WithAdminEmails(adminEmails),
		scoreboard.WithAllowedOrigins(allowedOrigins),
		scoreboard.WithJourneys(journeys),
		scoreboard.WithFalcoRules(falcoRules),
		scoreboard.WithOrder(order),
		scoreboard.WithDocsBaseURL(docsBaseURL),
		scoreboard.WithDetect(detectCfg),
		scoreboard.WithPoints(points),
		scoreboard.WithTtydSuffix(portalTtydSuffix),
	)

	// Auto-solve sweeper (P16): re-derives exfil-delivered-but-unsolved evade
	// pairs from the store every tick and auto-solves any whose clean window is
	// met, so participants need not manually submit. Runs in its own goroutine
	// bound to sweepCtx; cancelled after Serve returns (SIGINT/SIGTERM) so the
	// ticker stops and the goroutine exits before we close the store.
	sweepCtx, cancelSweep := context.WithCancel(context.Background())
	var sweepWG sync.WaitGroup
	sweepWG.Add(1)
	go func() {
		defer sweepWG.Done()
		handler.Sweeper().Run(sweepCtx)
	}()

	err = serverutil.Serve(addr, handler, logger, func() {
		logger.Info("listening", "addr", addr)
	})
	// Serve has returned (shutdown or listen error): stop the sweeper and wait
	// for its goroutine before the deferred st.Close() runs, so no sweep is
	// mid-MarkSolved against a closing DB.
	cancelSweep()
	sweepWG.Wait()
	if err != nil {
		logger.Error("listen failed", "err", err)
		os.Exit(1)
	}
}
