// Package api serves the read-side JSON state view, the flag-submission
// endpoint for evade-type challenges, the collector-only exfil sink, and the
// participant-facing Journey UI projection + progression writes.
//
//	GET  /api/state
//	POST /api/challenges/{cid}/submit
//	POST /internal/exfil/{cid}   (collector-only sink; see exfilInternal)
//	GET  /api/users/{user}/me
//	GET  /api/users/{user}/journey
//	POST /api/users/{user}/challenges/{cid}/steps/{idx}/check
//	POST /api/users/{user}/challenges/{cid}/hints/{idx}
//	POST /api/users/{user}/challenges/{cid}/reset-dirty
//	POST /api/users/{user}/display-name
//	GET  /api/hints
//	POST /api/admin/hints
//	POST /api/admin/reset
//	POST /api/admin/users/{user}/display-name
//	GET  /api/users/{user}/questions
//	POST /api/users/{user}/questions
//	GET  /api/users/{user}/questions/{qid}
//	POST /api/users/{user}/questions/{qid}/messages
//	GET  /api/admin/questions
//	GET  /api/admin/questions/{qid}
//	POST /api/admin/questions/{qid}/reply
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/qa"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/detect"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/originguard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// validUser matches the auth-derived identity username slug — same shape
// auth-policy enforces on incoming /check?host=… so the two sides agree.
var validUser = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// validMission matches a mission directory slug (e.g. "01-initial-recon"),
// the data-mission key the docs site sends when releasing a hint.
var validMission = regexp.MustCompile(`^[0-9]{2}-[a-z0-9-]{1,60}$`)

// invalidDisplayName rejects characters that would break either UI
// rendering (HTML metachars) or shell display (control chars). A 32-rune
// max keeps leaderboard columns predictable.
var invalidDisplayName = regexp.MustCompile(`[<>&"'\x00-\x1f\x7f]`)

// triggerDetectWindowSeconds is the lookback the Journey UI uses to surface
// which of a trigger mission's expectedRules the participant has already fired
// (detectedRules). It is a UI-DISPLAY-ONLY lookback: the actual solve verdict
// is owned entirely by the ingest → Grader.OnRuleFire path and is independent
// of this window (a rule fire records the solve the instant it arrives,
// regardless of what this projection shows). It is deliberately the same 60s
// window /me uses for its rule-fire feed so the two agree on screen.
// Signpost: if a future grader ever gains a windowed trigger verdict, this
// value and the grader's window should be sourced from one place.
//
// Distinct from the evade forbiddenRules taint gate (ADR-0003 attempt scope):
// that gate has NO time window at all (persistent, cleared only by an
// explicit reset) — see catalog.go's forbiddenRules doc and
// scoring.Grader.markDirtyOnRuleFire. Do not conflate the two "window"
// concepts; this one purely feeds a UI live-status cue.
const triggerDetectWindowSeconds = 60

// JourneyConfig carries the /journey UI inputs into the api handler:
// narrative content, the mission progression order, and the docs-site origin.
// All are optional — the handler applies safe defaults (see New).
type JourneyConfig struct {
	Journeys catalog.Journeys // challengeId -> narrative content (may be nil)
	// FalcoRules is the Story tab's display-only Falco rule excerpt
	// (challengeId -> List/Macro/Rule, from challenges/<NN>-<slug>/rule.yaml —
	// P23 Story-as-docs). May be nil; a missing entry means "no rule.yaml
	// authored for this challenge" and the UI omits the Falco Rule panel.
	// Content is identical for every viewer (no per-user secret), so exposing
	// it for ANY mission — solved, current, or locked — carries no fairness
	// risk (unlike hints, which stay gated to the unlocked prefix; see
	// missionDetail's lockedHints note).
	FalcoRules catalog.FalcoRuleExcerpts
	Order      []string // mission sequence (scenario order or catalog ids)
	// DocsBaseURL is the participant docs-site origin (e.g. https://docs.<suffix>).
	// When non-empty, each mission's relative docsUrl is rewritten to an absolute
	// URL under this origin. Empty = keep the relative path.
	DocsBaseURL string
}

type Handler struct {
	cat                catalog.Catalog
	store              *store.Store
	grader             *scoring.Grader
	logger             *slog.Logger
	now                func() time.Time
	submitLimiter      *ratelimit.Limiter
	displayNameLimiter *ratelimit.Limiter
	adminSet           map[string]struct{}
	originGuard        *originguard.Guard

	journeys    catalog.Journeys
	falcoRules  catalog.FalcoRuleExcerpts
	order       []string
	docsBaseURL string // docs-site origin for absolutising docsUrl; "" = relative

	// detect challenge grading (nil when no runner is configured — then
	// /submit-detect returns 503). detectInflight is a buffered channel used as a
	// counting semaphore: a slot is acquired non-blockingly before a grade and
	// released after, so a flood of submissions is REJECTED with 429 past the cap
	// rather than queued (design §3.3 — the net-new DoS lever). Its capacity is
	// the hard global in-flight grader cap.
	detectRunner   scoring.DetectRunner
	detectInflight chan struct{}

	// qa is the P25 QA ticket-chat store (ADR-0006). nil is possible only in
	// tests that never wire QAConfig — cmd/scoreboard/main.go always opens
	// one, unconditionally (there is no "QA disabled" feature flag, unlike
	// DetectConfig's Runner). Every qa route handler is reached only after a
	// gate (selfOrAdmin/selfOrAdminWrite/isAdmin) has already run, so a nil
	// qa here would only ever be dereferenced by a legitimately-authorized
	// caller in a misconfigured deployment — acceptable because that is
	// exactly the shape of every other required-but-unwired dependency in
	// this Handler (e.g. a nil store would panic just as readily).
	qa              *qa.Store
	questionLimiter *ratelimit.Limiter
}

// QAConfig carries the P25 QA ticket-chat store (ADR-0006) into the api
// handler. A separate config struct (matching JourneyConfig/DetectConfig's
// shape) rather than a bare *qa.Store parameter, so New's signature reads
// the same way for every optional subsystem this Handler wires.
type QAConfig struct {
	Store *qa.Store
}

// DetectConfig carries the detect-challenge grading inputs. Both fields are
// optional: when Runner is nil the /submit-detect endpoint returns 503 (feature
// off — e.g. local dev with no falco). InflightCap <= 0 falls back to
// DefaultDetectInflightCap.
type DetectConfig struct {
	Runner      scoring.DetectRunner
	InflightCap int
}

// DefaultDetectInflightCap bounds concurrent grader executions globally. A
// per-submission grader (docker/Job) is the net-new amplification vector; this
// hard cap (rejected past it with 429, never queued) plus the per-IP submit
// limiter keeps a flood from spawning unbounded work (design §3.3).
const DefaultDetectInflightCap = 5

// DetectGradeTimeout bounds a single detect grade end-to-end (compile gate +
// both replays). It is the deadline the handler puts on the context handed to
// SubmitDetect → DetectRunner, so a hung Falco invocation cannot occupy an
// in-flight slot forever (design §3.3). 30s sits just above the K8s-Job's
// activeDeadlineSeconds (~20s) so the Job's own deadline usually fires first;
// this is the app-side backstop for the local/docker path and for a stuck
// wait. On expiry the runner returns an infra error → 500 (fail-closed).
const DetectGradeTimeout = 30 * time.Second

// allowedOrigins is the ALLOWED_ORIGINS allowlist (P23-2) consumed by
// originguard to protect the browser-facing state-changing routes (see
// Register). Empty = every guarded request is denied (fail-closed) — see
// cmd/scoreboard/main.go for the deploy-time default and rationale.
func New(cat catalog.Catalog, grader *scoring.Grader, s *store.Store, logger *slog.Logger, now func() time.Time, adminEmails []string, allowedOrigins []string, jc JourneyConfig, dc DetectConfig, qc QAConfig) *Handler {
	// /submit accepts a claimed user identity. Without per-IP throttling a
	// participant who scraped someone else's flag could brute-force submits.
	// 1 req/s with burst 10 lets legitimate typing through but blocks
	// automated flooding.
	adminSet := newAdminSet(adminEmails)
	journeys := jc.Journeys
	if journeys == nil {
		journeys = catalog.Journeys{}
	}
	falcoRules := jc.FalcoRules
	if falcoRules == nil {
		falcoRules = catalog.FalcoRuleExcerpts{}
	}
	order := jc.Order
	if order == nil {
		order = cat.IDs()
	}
	// Normalise the docs origin to have no trailing slash so we can join with the
	// mission's relative docsUrl (which starts with "/") without doubling it.
	docsBaseURL := strings.TrimRight(strings.TrimSpace(jc.DocsBaseURL), "/")
	cap := dc.InflightCap
	if cap <= 0 {
		cap = DefaultDetectInflightCap
	}
	var inflight chan struct{}
	if dc.Runner != nil {
		inflight = make(chan struct{}, cap)
	}
	return &Handler{
		cat:                cat,
		store:              s,
		grader:             grader,
		logger:             logger,
		now:                now,
		submitLimiter:      ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
		displayNameLimiter: ratelimit.New(0.2 /* one every 5s */, 5 /* burst */).WithNow(now),
		adminSet:           adminSet,
		originGuard:        originguard.New(allowedOrigins, logger),
		journeys:           journeys,
		falcoRules:         falcoRules,
		order:              order,
		docsBaseURL:        docsBaseURL,
		detectRunner:       dc.Runner,
		detectInflight:     inflight,
		qa:                 qc.Store,
		// ADR-0006 Decision 1: 10s/1 refill, burst 3 — shared by ticket
		// creation and follow-up messages (ratelimit.ClientIP-keyed), so a
		// spammer cannot dodge the bucket by spreading posts across many
		// ticket ids.
		questionLimiter: ratelimit.New(0.1 /* one every 10s */, 3 /* burst */).WithNow(now),
	}
}

// newAdminSet normalises the ADMIN_EMAILS allowlist into a lookup set
// (trimmed, lower-cased, blanks dropped). Single definition shared by the api
// handler and the exported NewAdminGate so the admin-identity rule is not
// duplicated across the read gate and the view (index) gate.
func newAdminSet(adminEmails []string) map[string]struct{} {
	set := make(map[string]struct{}, len(adminEmails))
	for _, e := range adminEmails {
		if e = strings.TrimSpace(strings.ToLower(e)); e != "" {
			set[e] = struct{}{}
		}
	}
	return set
}

// NewAdminGate returns a predicate reporting whether a request carries an admin
// identity (X-Auth-Request-Email ∈ ADMIN_EMAILS, case-insensitive). It is the
// exact rule isAdmin uses, exported so the view package can gate the operator
// index page (P18-1) without re-implementing the check. Empty allowlist =
// nobody (fail-closed); a missing/blank header is not admin.
func NewAdminGate(adminEmails []string) func(*http.Request) bool {
	set := newAdminSet(adminEmails)
	return func(r *http.Request) bool {
		email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
		if email == "" {
			return false
		}
		_, ok := set[email]
		return ok
	}
}

// DeriveUsername extracts the display-only username slug from a request's
// X-Auth-Request-Email header, for the SOLE purpose of pre-filling the portal
// shell's Journey/Me pane identity (P23-1) — it is a UI convenience, never an
// authorization decision. Returns "" when the header is absent or the prefix
// before "@" is not a valid username slug (validUser) — in that case the
// portal shows an empty state asking the participant to check with the
// operator for their username, or to reload the portal after logging in
// again; there is no "?user=" manual-entry affordance.
//
// This is deliberately NOT the authorization boundary: whatever username this
// returns, every read/write the Journey/Me panes make is independently
// re-checked by selfOrAdmin / selfOrAdminWrite against the SAME
// X-Auth-Request-Email header server-side (I8-mirrored prefix-exact). A caller
// cannot use this function to see another user's data — it can only ever
// return the caller's OWN derived slug (or admin's own, which is not a
// participant identity and typically has no journey/me data of its own).
func DeriveUsername(r *http.Request) string {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		return ""
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	user := email[:at]
	if !validUser.MatchString(user) {
		return ""
	}
	return user
}

// og wraps a handler with the origin guard (P23-2). Applied to browser-only
// state-changing routes. NOT applied to routes that are also (or solely)
// reached via the collector's server-to-server forward — see each route's
// own comment below for why it is excluded (POST /internal/exfil/{cid},
// POST /api/challenges/{cid}/submit, POST
// /api/users/{user}/display-name).
func (h *Handler) og(next http.Handler) http.Handler {
	return h.originGuard.Middleware(next)
}

// Routes returns the api package's declarative route table (ADR-0005 V2) —
// the single artifact scoreboard.Handler's NewHandler feeds into
// apispec.Register, and (via that same call's return value) what the parity
// tests (internal/scoreboard's *_test.go) compare against
// docs/openapi-scoreboard.yaml. Every route's OriginGuarded /
// CollectorForward value below is repeated, unchanged, from the per-route
// comments that used to live only beside the old mux.Handle calls; see
// og's doc for the general shape of the asymmetry and each entry below for
// the route-specific reasoning.
//
// This package deliberately has no Register(mux) method of its own (LOW, 5x
// review: one used to exist here, calling apispec.Register(mux, h.Routes())
// directly, but nothing in this codebase — production or test — ever called
// it; scoreboard.Handler's NewHandler always collects every sub-package's
// Routes() into one table and calls apispec.Register exactly once). A
// second, unused registration entry point contradicted I14's "single
// registration path" claim on its face, even though it happened to be dead;
// it was removed rather than documented as test-only, since it had no test
// either.
func (h *Handler) Routes() []apispec.Route {
	submitMW := h.submitLimiter.Middleware(ratelimit.ClientIP)
	dnMW := h.displayNameLimiter.Middleware(ratelimit.ClientIP)
	questionMW := h.questionLimiter.Middleware(ratelimit.ClientIP)
	return []apispec.Route{
		{
			Method: "GET", Pattern: "/api/state",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.state),
		},
		{
			Method: "GET", Pattern: "/api/users/{user}/me",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.userMe),
		},
		{
			Method: "GET", Pattern: "/api/users/{user}/journey",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.journey),
		},
		{
			// The most destructive route in this service — the origin guard's
			// actual target (ADR-0005 Decision 4).
			Method: "POST", Pattern: "/api/admin/reset",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.reset)),
		},
		{
			// The operator dashboard's rename button calls this route, which is
			// why it stays origin-guarded (unlike the participant-facing
			// display-name route below, whose only caller is the collector).
			Method: "POST", Pattern: "/api/admin/users/{user}/display-name",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.adminSetDisplayName)),
		},
		{
			// Deliberately unauthenticated (Decision 5 does not apply): carries
			// no per-user data or hint TEXT, only released indices.
			Method: "GET", Pattern: "/api/hints",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzNone,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.hints),
		},
		{
			Method: "POST", Pattern: "/api/admin/hints",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.releaseHint)),
		},
		{
			// NOT wrapped by the origin guard (P23-2 follow-up). This route has
			// TWO callers: the journey UI (browser fetch, carries Origin) AND the
			// collector's verbatim forward of the participant's curl submission
			// (internal/collector/collector.go — "Routes fronted"; curl sends no
			// Origin/Referer at all). Egress lockdown makes the collector-forwarded
			// curl path the PRIMARY flag-submission route once a workspace can no
			// longer reach the scoreboard directly, so a fail-closed Origin gate
			// here would 403 every legitimate submission via that path and break
			// scoring — exactly the class of regression this middleware must never
			// cause. The CSRF this would otherwise mitigate (an attacker riding a
			// victim's session to submit — and thereby credit — a flag the
			// attacker chose) has no destructive blast radius comparable to
			// /api/admin/reset (the mitigation's actual target): at most it
			// credits a solve, it does not delete state or read another user's
			// data. Accepted residual risk; revisit only if submit ever gains a
			// destructive side effect.
			Method: "POST", Pattern: "/api/challenges/{cid}/submit",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzClaimedIdentity,
			OriginGuarded: false, CollectorForward: true,
			RateLimit: "per-IP 1 req/s burst 10 (shared with submit-detect)",
			Handler:   submitMW(http.HandlerFunc(h.submit)),
		},
		{
			// Detect grading reuses the SAME per-IP submit limiter (same trust
			// model as /submit) plus a global in-flight cap enforced inside the
			// handler (429 past it, never queued). Unlike /submit above, this
			// route has only ONE caller: the journey UI's browser fetch (the
			// "Grade" button on a detect mission's condition textarea —
			// docs/detect-challenge-design.md §6). The collector's forward
			// allowlist (internal/collector/collector.go — "Routes fronted") does
			// NOT include submit-detect, so there is no server-to-server curl
			// caller to protect against a fail-closed gate here — same reasoning
			// as steps/{idx}/check and hints/{idx} below. Origin-guarded.
			Method: "POST", Pattern: "/api/challenges/{cid}/submit-detect",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "per-IP 1 req/s burst 10 + global in-flight grader cap (5)",
			Handler:   h.og(submitMW(http.HandlerFunc(h.submitDetect))),
		},
		{
			// Exfil is an internal-only endpoint reached solely by the collector
			// (full one-pipe, P11.5). Workspaces cannot reach the scoreboard
			// directly once egress lockdown is on — they POST
			// /api/challenges/{cid}/exfil to the collector, which forwards to
			// /internal/exfil here. Isolation is enforced by NetworkPolicy
			// (scoreboard ingress admits only collector); the handler itself adds
			// no auth (see recordExfil doc). Rate limiting lives on the collector
			// front, so /internal/exfil is unthrottled here. It is also
			// DELIBERATELY NOT wrapped by the origin guard (P23-2): this is a
			// server-to-server request with no browser Origin/Referer, so gating
			// it would 403 every legitimate exfil receipt and silently break the
			// boss capstone's scoring path.
			Method: "POST", Pattern: "/internal/exfil/{cid}",
			Audience: apispec.AudienceInternal, Authz: apispec.AuthzClaimedIdentity,
			OriginGuarded: false, CollectorForward: true,
			RateLimit: "none (the limit lives on the collector front)",
			Handler:   http.HandlerFunc(h.exfilInternal),
		},
		{
			// Journey progression writes (self-check ticks). Rate-limited on the
			// same bucket as /submit — participant-facing writes. This IS
			// origin-guarded: unlike submit/display-name below, it is reached
			// ONLY from the portal's Journey pane browser fetch
			// (templates/portal.html) — the collector's forward allowlist
			// (internal/collector/collector.go) does not include
			// steps/{idx}/check — so there is no server-to-server caller to
			// protect against a fail-closed gate here.
			Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/steps/{idx}/check",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "per-IP 1 req/s burst 10",
			Handler:   h.og(submitMW(http.HandlerFunc(h.stepCheck))),
		},
		{
			// Progressive hint reveal — same reasoning as steps/check above, plus
			// a second one: the 409/200 distinction is a cross-user oracle if an
			// unauthenticated caller can drive it.
			Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/hints/{idx}",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "per-IP 1 req/s burst 10",
			Handler:   h.og(submitMW(http.HandlerFunc(h.openHint))),
		},
		{
			// App-H2: the explicit, self-scoped escape hatch from the persistent
			// evade dirty flag (internal/store MarkDirty/DirtyRules). Same trust
			// model and route family as steps/check and hints/{idx} above —
			// reached ONLY from the portal's Journey pane browser fetch, never
			// from the collector's forward allowlist — so it is origin-guarded
			// and self/admin-write gated the same way.
			//
			// Do NOT remove the origin guard from this route and do NOT add it
			// to the collector's forward allowlist: ADR-0003 A2-2 made this
			// endpoint able to delete another participant's exfil receipt, and
			// the header-less claimed-identity fallback in selfOrAdminWrite
			// carries no proof the caller IS {user}. The guard 403s exactly the
			// shape a header-less cluster-internal caller sends, BEFORE the
			// self-or-admin check runs — that is what keeps A2-2's destructive
			// reset from becoming an unauthenticated cross-user action (app#124
			// 5x, R1 C3). This is also why ADR-0005 V4 asserts, as a dedicated
			// check (not just a bijection count), that reset-dirty never appears
			// in the collector-forward set.
			Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/reset-dirty",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "per-IP 1 req/s burst 10",
			Handler:   h.og(submitMW(http.HandlerFunc(h.resetDirty))),
		},
		{
			// NOT wrapped by the origin guard (P23-2 follow-up). Unlike submit
			// above, this route has only ONE caller: the collector's verbatim
			// forward (internal/collector/collector.go — "Routes fronted") of the
			// participant's curl-issued display-name update. No browser template
			// in this repo fetches this participant-facing path directly (the
			// journey UI has no such call; the only browser caller of a
			// display-name endpoint is index.html's ADMIN
			// /api/admin/users/{user}/display-name, a distinct route that stays
			// origin-guarded above). A fail-closed gate here would therefore 403
			// every legitimate call with no browser-CSRF surface to protect in
			// exchange.
			Method: "POST", Pattern: "/api/users/{user}/display-name",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: false, CollectorForward: true,
			RateLimit: "per-IP 1 req / 5s burst 5",
			Handler:   dnMW(http.HandlerFunc(h.setDisplayName)),
		},
		{
			// P25 (ADR-0006): the caller's own QA ticket summaries. Reads are
			// never origin-guarded or rate-limited (same posture as the other
			// self-scoped reads above — /me, /journey).
			Method: "GET", Pattern: "/api/users/{user}/questions",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.listQuestions),
		},
		{
			// Opens a new ticket. Origin-guarded + selfOrAdminWrite (the same
			// two-gate stack steps/check and hints/{idx} use above): reached
			// ONLY from the portal's browser fetch, never from the collector's
			// forward allowlist (ADR-0006 explicitly declines to add QA there
			// — a participant's QA send has no legitimate workspace/curl
			// caller, so adding it would only widen the attack surface).
			// Shares questionLimiter's bucket with postMessage below.
			Method: "POST", Pattern: "/api/users/{user}/questions",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "per-IP 1 req/10s burst 3 (shared with postQuestionMessage)",
			Handler:   h.og(questionMW(http.HandlerFunc(h.createQuestion))),
		},
		{
			// One ticket's full thread. The composite (id,user) ownership
			// check lives inside qa.Store.GetThreadForUser (ADR-0006 Decision
			// 2) — selfOrAdmin only proves the caller MAY act as {user}, it
			// says nothing about whether {qid} belongs to {user}.
			Method: "GET", Pattern: "/api/users/{user}/questions/{qid}",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.getQuestion),
		},
		{
			// Follow-up message on the caller's own ticket. Same origin-guard
			// + selfOrAdminWrite + shared rate-limit bucket as createQuestion
			// above; the composite-key ownership check + insert happen inside
			// ONE qa.Store call (AppendMessageForUser), never two round trips
			// (ADR-0006 Decision 2 / security-engineer finding 4).
			Method: "POST", Pattern: "/api/users/{user}/questions/{qid}/messages",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdminWrite,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "per-IP 1 req/10s burst 3 (shared with createQuestion)",
			Handler:   h.og(questionMW(http.HandlerFunc(h.postMessage))),
		},
		{
			// Operator's full ticket list, every participant. No {user} in
			// this route — it is a standalone admin route, not a self-scoped
			// one (ADR-0006 Decision 1).
			Method: "GET", Pattern: "/api/admin/questions",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.adminListQuestions),
		},
		{
			// One ticket, any participant, by id alone — admin routes do not
			// go through {user}, so there is no composite key to check
			// (ADR-0006 Decision 2: isAdmin alone is the intended gate here).
			Method: "GET", Pattern: "/api/admin/questions/{qid}",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.adminGetQuestion),
		},
		{
			// THE only legitimate operator reply path (ADR-0006 Decision 1 /
			// security-engineer finding 5 — see adminReply's own doc for why
			// this matters even though selfOrAdminWrite's admin branch would
			// technically also let an admin post through the participant
			// route). Origin-guarded like the operator dashboard's other
			// admin writes (reset / hints / display-name above); never
			// rate-limited, matching that same trusted-actor precedent.
			Method: "POST", Pattern: "/api/admin/questions/{qid}/reply",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.adminReply)),
		},
	}
}

// --- admin reset ------------------------------------------------------------

// isAdmin reports whether the request carries an admin identity. The admin
// email is propagated by auth-policy (X-Auth-Request-Email) only on the
// admin-gated ingress path; requests over the cluster-internal Service
// (workspace/falco) carry no such header and are rejected. Empty allowlist =
// nobody (fail-closed).
func (h *Handler) isAdmin(r *http.Request) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		return "", false
	}
	_, ok := h.adminSet[email]
	return email, ok
}

// emailMatchesUser reports whether the auth-derived caller email belongs to the
// given username slug, using the SAME prefix-exact rule auth-policy /check
// enforces (conventions I8): the email must begin with "<user>@". This is a
// mirror — not a shared import — because auth-policy is a separate service /
// binary (see CLAUDE.md); the semantics ("email == username+"@"+domain",
// domain-agnostic) are reproduced here so the two auth boundaries agree.
//
// Not a verbatim mirror: this is a LOWERCASE-NORMALISED prefix-exact match. The
// callers (selfOrAdmin / selfOrAdminWrite) lower-case the header before calling
// in, whereas auth-policy /check (internal/authpolicy/server.go, the raw
// strings.HasPrefix on X-Auth-Request-Email) compares the email verbatim. The
// normalisation only ever makes THIS side STRICTER-or-equal (case-folding can
// grant no match the raw check would deny), so it cannot open a hole the auth
// boundary closes. Signpost: on an IdP swap (email casing / claim shape change),
// auth-policy /check and emailMatchesUser must be revisited together — they are
// the two halves of the same cross-user isolation invariant (I8).
//
// Prefix-exact is deliberate and NOT a substring match: "user1@…" is required,
// so a caller "user10@…" or "user1x@…" does NOT satisfy user="user1" — the
// character after "user1" is the literal '@', and "user10@" has '0' there, so
// HasPrefix("user10@…", "user1@") is false. This is the exact anti-mismatch
// property auth-policy relies on for cross-user workspace isolation.
func emailMatchesUser(email, user string) bool {
	if email == "" || user == "" {
		return false
	}
	return strings.HasPrefix(email, user+"@")
}

// selfOrAdmin is the participant-facing read gate (P18). It derives the caller
// identity from X-Auth-Request-Email — the header oauth2-proxy injects on the
// single-origin portal host (P19-2b: `app.<dnsSuffix>/portal`, journey being
// one of the portal's tabs rather than its own host) and that auth-policy
// also propagates on the admin host — and authorizes the request for {user}
// iff:
//
//   - the caller email prefix-exact matches "<user>@" (self, I8-mirrored), OR
//   - the caller email is in ADMIN_EMAILS (operator override — the one
//     intentional exception, identical to auth-policy /check).
//
// A missing or blank header is denied (fail-closed): the self-claimed {user}
// path param is never trusted on its own. This is what keeps a participant from
// reading another participant's journey/progress over the participant host.
//
// Design note (host distinction): the gate keys off the PRESENCE + VALUE of the
// auth header rather than which ingress host was used. Both participant and
// admin hosts are auth-proxied and inject X-Auth-Request-Email; the
// cluster-internal Service path (workspace pods, collector, Falco) injects no
// such header and is therefore denied here. This is the minimal safe signal —
// the scoreboard need not know the hostname, and the header cannot be forged
// from inside the cluster because the internal Service path never sets it and
// ingress strips/overwrites any client-supplied copy (auth-request headers are
// set by oauth2-proxy, not passed through from the client).
func (h *Handler) selfOrAdmin(w http.ResponseWriter, r *http.Request, user string) bool {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		// fail-closed: no proven identity → deny (do not fall back to {user}).
		h.logger.Warn("read gate denied: missing identity", "remote_addr", r.RemoteAddr, "user", user)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return false
	}
	if _, ok := h.adminSet[email]; ok {
		return true
	}
	if emailMatchesUser(email, user) {
		return true
	}
	h.logger.Warn("read gate denied: identity mismatch", "remote_addr", r.RemoteAddr, "user", user, "email", email)
	httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
	return false
}

// selfOrAdminWrite is the participant-facing WRITE gate for /api/users/{user}/*
// mutations (step-check, hint reveal, display-name). It differs from the read
// gate (selfOrAdmin) by being conditional on the PRESENCE of an auth header:
//
//   - Header present (request arrived over an auth-proxied ingress host — the
//     participant journey host or the admin host): apply the full self-or-admin
//     rule. A logged-in participant may only mutate their OWN {user}; a mismatch
//     or a non-admin third party is denied (403). Admins may write any {user}.
//     This closes the P18 HIGH: on the journey host, oauth2-proxy injects
//     X-Auth-Request-Email for ANY login, so without this a participant could
//     tick another participant's steps, drive the openHint 409/200 cross-user
//     oracle, or overwrite another player's display name.
//
//   - Header absent (request arrived over the cluster-internal Service — the
//     collector's display-name forward, or a workspace pod): fall back to the
//     legacy claimed-identity trust model (allow). This path carries no proven
//     identity and never has; NetworkPolicy is the isolation control there. Not
//     loosening it keeps the collector-fronted display-name flow working
//     (accepted LOW) and the write collector path unchanged.
//
// Rationale for keying off header presence (not hostname): identical to
// selfOrAdmin's design note — both auth-proxied hosts inject the header and the
// internal Service path never does; ingress overwrites any client-supplied copy
// (auth-response-headers), so the header cannot be forged from inside the
// cluster. Returns true when the request may proceed; writes a 403 and returns
// false otherwise.
func (h *Handler) selfOrAdminWrite(w http.ResponseWriter, r *http.Request, user string) bool {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		// Cluster-internal (collector / workspace): no auth header ever set here.
		// Preserve the claimed-identity model — isolation is NetworkPolicy's job.
		return true
	}
	// Auth-proxied host (journey/admin): enforce self-or-admin on the proven id.
	if _, ok := h.adminSet[email]; ok {
		return true
	}
	if emailMatchesUser(email, user) {
		return true
	}
	h.logger.Warn("write gate denied: identity mismatch", "remote_addr", r.RemoteAddr, "user", user, "email", email)
	httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
	return false
}

// reset wipes the scoreboard results (solves + event counters), e.g. after a
// test1 demo run before the real event. Admin-only (see isAdmin).
func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	email, ok := h.isAdmin(r)
	if !ok {
		h.logger.Warn("reset denied", "remote_addr", r.RemoteAddr, "email", email)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	n, err := h.store.Reset()
	if err != nil {
		h.logger.Error("reset failed", "err", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	h.logger.Info("scoreboard reset", "by", email, "cleared_solves", n)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared_solves": n})
}

// --- operator-controlled hints ---------------------------------------------

// hints returns the operator-released hints as {mission: [hintIdx...]}. Public
// read: the participant docs site polls this and reveals only released hints
// (replaces the old client-side timer, which couldn't be coordinated fairly).
func (h *Handler) hints(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"released": h.store.ReleasedHints()})
}

// releaseHint releases (or revokes) one mission hint to participants. Admin-only
// (see isAdmin). Body: {"mission":"01-initial-recon","hint":1,"released":true}.
func (h *Handler) releaseHint(w http.ResponseWriter, r *http.Request) {
	email, ok := h.isAdmin(r)
	if !ok {
		h.logger.Warn("hint release denied", "remote_addr", r.RemoteAddr, "email", email)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req struct {
		Mission  string `json:"mission"`
		Hint     int    `json:"hint"`
		Released bool   `json:"released"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !validMission.MatchString(req.Mission) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid mission"})
		return
	}
	if req.Hint < 1 || req.Hint > 20 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid hint index"})
		return
	}
	if err := h.store.ReleaseHint(req.Mission, req.Hint, req.Released, h.now().UTC().Format(time.RFC3339)); err != nil {
		h.logger.Error("hint release failed", "err", err)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	h.logger.Info("hint release", "by", email, "mission", req.Mission, "hint", req.Hint, "released", req.Released)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "mission": req.Mission, "hint": req.Hint, "released": req.Released})
}

// validDisplayName trims + validates a display name: 1..32 runes, no HTML/shell
// metachars. Shared by the participant and admin set endpoints.
func validDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("name required")
	}
	if utf8.RuneCountInString(name) > 32 {
		return "", fmt.Errorf("name too long (max 32 runes)")
	}
	if invalidDisplayName.MatchString(name) {
		return "", fmt.Errorf("name contains forbidden characters")
	}
	return name, nil
}

// adminSetDisplayName sets or OVERWRITES any user's display name (operator
// override, last-write-wins). Admin-only (see isAdmin). Lets the operator
// assign/correct scoreboard names; default stays the username when unset.
func (h *Handler) adminSetDisplayName(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.isAdmin(r); !ok {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	name, err := validDisplayName(req.Name)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.store.SetDisplayName(user, name, at); err != nil {
		h.logger.Error("admin set display name", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	h.logger.Info("admin display_name", "user", user, "display_name", name, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user, "display_name": name})
}

// --- submit -----------------------------------------------------------------

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	// auditLog: every branch below records a structured line so post-event
	// triage can answer "who submitted what flag against which challenge",
	// even when the result is rejection. Identity (`user`) is claimed by
	// the request body — never verified — so always log the source address
	// alongside it for cross-referencing.
	auditLog := func(outcome string, extra ...any) {
		fields := []any{
			"cid", cid,
			"remote_addr", r.RemoteAddr,
			"outcome", outcome,
		}
		fields = append(fields, extra...)
		h.logger.Info("submit", fields...)
	}

	// The two pre-body guards (unknown challenge / not an evade challenge) stay
	// here because they gate whether we even read the request body — but their
	// verdict is the Grader's (SubmitEvade returns the same statuses). We peek
	// the catalog for the pre-body guards, then hand the full decision to the
	// Grader once we have user+flag.
	if _, ok := h.cat[cid]; !ok {
		metrics.SubmissionsTotal.WithLabelValues(cid, "unknown_challenge").Inc()
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	if h.cat[cid].Type != "evade" {
		metrics.SubmissionsTotal.WithLabelValues(cid, "not_evade").Inc()
		auditLog("not_evade")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": cid + " is not an evade challenge"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req oapi.SubmitFlagJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "err", err.Error())
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	user := strings.TrimSpace(req.User)
	flag := strings.TrimSpace(req.Flag)

	if user == "" {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "reason", "missing user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user required"})
		return
	}

	// Solve decision (flag match → evade window → exfil gate → record) is the
	// Grader's. This handler only translates the outcome into a response +
	// metric + audit line. The window is evaluated against server time inside
	// the Grader (App-H3) — the handler never passes attacker-supplied time.
	outcome, err := h.grader.SubmitEvade(user, cid, flag)
	if err != nil {
		// Fail closed: a store error must never surface as a silent empty 200.
		// EvadeUnknownChallenge (=0) has no switch case, so returning the
		// zero-value outcome below would drop the solve without a body or a
		// distinguishable audit line — a correctly-evaded solve would vanish on
		// a transient DB error. Mirror exfilInternal's store-error path: log,
		// audit, and return a 500 (no new metric label; exfilInternal adds none
		// either, keeping cardinality bounded).
		h.logger.Error("mark solved", "err", err)
		auditLog("error", "user", user, "err", err.Error())
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not record solve"})
		return
	}
	switch outcome.Status {
	case scoring.EvadeWrongFlag:
		metrics.SubmissionsTotal.WithLabelValues(cid, "wrong_flag").Inc()
		auditLog("wrong_flag", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"correct": false, "reason": "flag mismatch"})
	case scoring.EvadeForbiddenFired:
		metrics.SubmissionsTotal.WithLabelValues(cid, "not_evaded").Inc()
		auditLog("not_evaded", "user", user, "offending_rules", outcome.Offending)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"correct": true,
			"evaded":  false,
			// App-H2 / ADR-0003 §A2: this is now a PERSISTENT taint, not a
			// recent-window warning — waiting does not help. This text must
			// NOT tell a participant to curl reset-dirty directly: that route
			// sits behind an origin-guard that 403s any request without a
			// browser-supplied Origin/Referer (see resetDirty's doc in this
			// file), so a workspace curl of the path below is unreachable —
			// it would be a dead-end instruction (app#125, prod gate). The
			// only participant-reachable path is the "このミッションをやり直す"
			// button the Journey UI renders on this mission's panel
			// (portal.html dirtySection); fall back to staff if it's missing.
			"reason": fmt.Sprintf(
				"flag is correct, but the forbidden rule(s) %v fired for user %q and this attempt "+
					"is now marked dirty. Waiting will not clear it — use the mission panel's "+
					"\"このミッションをやり直す\" (redo this mission) button in the portal to reset, "+
					"redo the attack cleanly, then submit again. If that button is unavailable, ask a staff member.",
				outcome.Offending, user,
			),
		})
	case scoring.EvadeExpectedRuleFireRequired:
		// ADR-0008: positive-proof gate — flag correct + not dirty, but none of
		// the mission's expectedRules has ever fired for this user. Declared
		// between EvadeForbiddenFired and EvadeExfilRequired to mirror
		// evaluateClean's gate order (dirty -> expectedRuleFire -> exfil ->
		// solve).
		metrics.SubmissionsTotal.WithLabelValues(cid, "not_proven").Inc()
		auditLog("not_proven", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"correct": true,
			"evaded":  true,
			"proven":  false,
			"reason": fmt.Sprintf(
				"flag is correct and the window is clean, but %q has not yet demonstrated the "+
					"evasion technique this mission requires — no matching Falco event has fired. "+
					"Follow the mission brief's technique, then submit again.",
				user,
			),
		})
	case scoring.EvadeExfilRequired:
		metrics.SubmissionsTotal.WithLabelValues(cid, "not_exfiltrated").Inc()
		auditLog("not_exfiltrated", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"correct":     true,
			"evaded":      true,
			"exfiltrated": false,
			"reason": fmt.Sprintf(
				"flag is correct and the window is clean, but %q has not exfiltrated it to the collector yet. "+
					"Deliver the flag over HTTP first: POST /api/challenges/%s/exfil — then submit.",
				user, cid,
			),
		})
	case scoring.EvadeSolved:
		if outcome.Newly {
			metrics.SolvesTotal.WithLabelValues(cid, "evade").Inc()
		}
		metrics.SubmissionsTotal.WithLabelValues(cid, "solved").Inc()
		auditLog("solved", "user", user, "newly", outcome.Newly, "display_name", h.store.DisplayName(user))
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"correct":      true,
			"evaded":       true,
			"solved":       true,
			"user":         user,
			"display_name": h.store.DisplayName(user),
		})
	}
}

// --- submit-detect ----------------------------------------------------------

// submitDetect grades a participant-authored Falco condition for a detect-type
// challenge. It reuses the /submit trust model (claimed identity, per-IP rate
// limiter middleware) and adds two detect-specific controls:
//
//   - self-scope: on an auth-proxied host the caller may only grade as its OWN
//     {user} (selfOrAdminWrite, the same gate step-check / display-name use). The
//     claimed body user must match the proven identity; an admin may grade for
//     any user. Over the cluster-internal path (no auth header) the legacy
//     claimed-identity model holds (NetworkPolicy is the isolation control there).
//   - global in-flight cap: a per-submission grader (docker/Job) is the net-new
//     DoS lever, so past detectInflight's capacity the request is REJECTED with
//     429 (never queued) — a flood cannot spawn unbounded grader work.
//
// The solve decision (compile gate → replay → pass) is the Grader's
// (SubmitDetect); this handler only translates the outcome. The reference
// condition / capture contents are NEVER returned — only the fire counts (safe
// pedagogic feedback).
func (h *Handler) submitDetect(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	auditLog := func(outcome string, extra ...any) {
		fields := []any{"cid", cid, "remote_addr", r.RemoteAddr, "outcome", outcome}
		fields = append(fields, extra...)
		h.logger.Info("submit_detect", fields...)
	}

	// Feature-off: no runner wired (local dev without falco). 503, not 404/500.
	if h.detectRunner == nil {
		auditLog("detect_disabled")
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "detect grading is not enabled"})
		return
	}

	// Pre-body guards (unknown challenge / not detect type) gate whether we read
	// the body — verdict is still the Grader's (SubmitDetect returns the same
	// statuses).
	ch, ok := h.cat[cid]
	if !ok {
		metrics.SubmissionsTotal.WithLabelValues(cid, "unknown_challenge").Inc()
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	if ch.Type != "detect" {
		metrics.SubmissionsTotal.WithLabelValues(cid, "not_detect").Inc()
		auditLog("not_detect")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": cid + " is not a detect challenge"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, detect.MaxConditionBytes+1<<10)
	var req oapi.SubmitDetectJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "err", err.Error())
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	user := strings.TrimSpace(req.User)
	condition := strings.TrimSpace(req.Condition)
	if user == "" {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "reason", "missing user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user required"})
		return
	}
	if !validUser.MatchString(user) {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "reason", "invalid user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	// Self-scope: on an auth-proxied host the claimed user must be the proven
	// identity (or admin). Uses validated `user` for the prefix-exact match.
	if !h.selfOrAdminWrite(w, r, user) {
		auditLog("forbidden", "user", user)
		return
	}
	if condition == "" {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "user", user, "reason", "missing condition")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "condition required"})
		return
	}
	if len(condition) > detect.MaxConditionBytes {
		metrics.SubmissionsTotal.WithLabelValues(cid, "bad_request").Inc()
		auditLog("bad_request", "user", user, "reason", "condition too large")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "condition too large"})
		return
	}

	// Global in-flight cap: acquire a slot NON-blockingly. Past the cap, reject
	// with 429 (no queueing) so a flood cannot spawn unbounded grader work.
	select {
	case h.detectInflight <- struct{}{}:
		defer func() { <-h.detectInflight }()
	default:
		metrics.SubmissionsTotal.WithLabelValues(cid, "rate_limited").Inc()
		auditLog("inflight_cap", "user", user)
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many in-flight grader jobs; retry shortly"})
		return
	}

	// Bound the grade: a hung Falco invocation (docker/Job) must not hold an
	// in-flight slot indefinitely (design §3.3 — the in-flight cap is the DoS
	// control, and a wedged grade would leak a slot until the client disconnects).
	// The deadline is derived from the server clock and propagated to the runner's
	// every falco call via ctx; it sits just above the Job's activeDeadlineSeconds
	// (~20s) so an infra timeout surfaces as a 500 (fail-closed), never a solve.
	ctx, cancel := context.WithTimeout(r.Context(), DetectGradeTimeout)
	defer cancel()
	outcome, err := h.grader.SubmitDetect(ctx, h.detectRunner, user, cid, condition)
	if err != nil {
		// Fail closed: a runner infra error is a 500, never a silent solve.
		h.logger.Error("grade detect", "err", err, "cid", cid, "user", user)
		auditLog("error", "user", user, "err", err.Error())
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not grade condition"})
		return
	}
	switch outcome.Status {
	case scoring.DetectInvalidCondition:
		metrics.SubmissionsTotal.WithLabelValues(cid, "detect_invalid").Inc()
		auditLog("invalid", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "invalid",
			"solved": false,
			"reason": "the condition did not compile (falco -V rejected it). Check the syntax and the macros you referenced.",
		})
	case scoring.DetectMissedEvasion:
		metrics.SubmissionsTotal.WithLabelValues(cid, "detect_missed").Inc()
		auditLog("missed", "user", user, "evasion_fires", outcome.EvasionFires, "benign_fires", outcome.BenignFires)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        "missed",
			"solved":        false,
			"evasion_fires": outcome.EvasionFires,
			"benign_fires":  outcome.BenignFires,
			"reason":        "your rule did not fire on the attack capture. It fired 0× on the evasion — it is not detecting the behaviour.",
		})
	case scoring.DetectFalsePositive:
		metrics.SubmissionsTotal.WithLabelValues(cid, "detect_false_positive").Inc()
		auditLog("false_positive", "user", user, "evasion_fires", outcome.EvasionFires, "benign_fires", outcome.BenignFires)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        "false-positive",
			"solved":        false,
			"evasion_fires": outcome.EvasionFires,
			"benign_fires":  outcome.BenignFires,
			"reason":        "your rule caught the attack but also fired on benign traffic — too broad. Tighten it so it fires 0× on the benign capture.",
		})
	case scoring.DetectSolved:
		if outcome.Newly {
			metrics.SolvesTotal.WithLabelValues(cid, "detect").Inc()
		}
		metrics.SubmissionsTotal.WithLabelValues(cid, "solved").Inc()
		auditLog("solved", "user", user, "newly", outcome.Newly, "evasion_fires", outcome.EvasionFires, "display_name", h.store.DisplayName(user))
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        "solved",
			"solved":        true,
			"evasion_fires": outcome.EvasionFires,
			"benign_fires":  outcome.BenignFires,
			"user":          user,
			"display_name":  h.store.DisplayName(user),
		})
	}
}

// --- internal exfil sink ----------------------------------------------------

// exfilInternal records an exfil receipt for the boss capstone. It is the
// internal-only sink behind the collector (P11.5 full one-pipe): the
// participant curls the flag to the collector's public
// POST /api/challenges/{cid}/exfil, and the collector forwards it here as
// POST /internal/exfil/{cid}. This is what forces the quiet-exfil lesson — a
// reverse shell (Run/C2 rules) can't reach an HTTP collector, and dropping a
// custom exfil tool trips Drop-and-execute.
//
// Trust model: identity (`user`) is claimed, never proven — same as /submit,
// logged for traceability. The endpoint adds no auth of its own; it is reached
// only from the collector (scoreboard NetworkPolicy admits collector, not
// ctf-user). The flag is matched at submit time (RequireExfil via HasExfil), so
// a wrong value recorded here simply fails the eventual submit.
func (h *Handler) exfilInternal(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	auditLog := func(outcome string, extra ...any) {
		fields := []any{"cid", cid, "remote_addr", r.RemoteAddr, "outcome", outcome}
		fields = append(fields, extra...)
		h.logger.Info("exfil_internal", fields...)
	}

	// Pre-body guards (unknown challenge / exfil not accepted) gate whether we
	// read the body at all, matching the prior order. Their verdict is the
	// Grader's — RecordExfil re-applies the same guards before recording.
	if _, ok := h.cat[cid]; !ok {
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	if !h.cat[cid].RequireExfil {
		auditLog("exfil_not_required")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": cid + " does not accept exfil"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req struct {
		User string `json:"user"`
		Flag string `json:"flag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		auditLog("bad_request", "err", err.Error())
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	user := strings.TrimSpace(req.User)
	flag := strings.TrimSpace(req.Flag)
	if user == "" || flag == "" {
		auditLog("bad_request", "reason", "missing user or flag")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user and flag required"})
		return
	}

	// Recording the collector receipt (with its catalog/RequireExfil guards and
	// receipt timestamp) is the Grader's job; the guards above have already
	// short-circuited the unknown / not-required cases, so here the Grader
	// returns ExfilRecorded (or a store error).
	if _, err := h.grader.RecordExfil(user, cid, flag); err != nil {
		h.logger.Error("record exfil", "err", err, "user", user, "cid", cid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not record exfil"})
		return
	}
	auditLog("received", "user", user)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"received": true,
		"user":     user,
		// App-H2: no time window anymore — "clean" means no forbidden rule has
		// EVER fired for this pair since the last explicit reset.
		"note": "collector received the data. Now submit the flag (the run must still be clean — " +
			"no forbidden rule may have fired since your last reset).",
	})
}

// --- Journey step self-check ------------------------------------------------

// stepCheck ticks (checked=true) or clears (checked=false) step {idx} (0-based)
// of {cid} for {user}. Purely presentational: journey `steps` are an info-only
// checklist with no auto-detection, so a tick never affects the solve verdict —
// it just lets a participant track their own progress across page reloads. Same
// claimed-identity trust model as /submit (logged, never proven).
//
// Body:  {"checked": true}
// Route: POST /api/users/{user}/challenges/{cid}/steps/{idx}/check
func (h *Handler) stepCheck(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	cid := r.PathValue("cid")
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdminWrite(w, r, user) {
		return
	}
	if _, ok := h.cat[cid]; !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	j, ok := h.journeys[cid]
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "no journey content for " + cid})
		return
	}
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 0 || idx >= len(j.Steps) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid step index"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req struct {
		Checked bool `json:"checked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	at := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.store.SetStepCheck(user, cid, idx, req.Checked, at); err != nil {
		h.logger.Error("set step check", "err", err, "user", user, "cid", cid, "idx", idx)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not record step check"})
		return
	}
	h.logger.Info("step_check", "user", user, "cid", cid, "idx", idx, "checked", req.Checked, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user, "cid": cid, "idx": idx, "checked": req.Checked})
}

// --- Journey progressive hint reveal ----------------------------------------

// openHint reveals hint {idx} (1-based) of {cid} for {user}. Hints must be
// opened in order: idx 1 first, then 2, etc. — opening idx N requires idx N-1
// already opened (so participants approach the answer progressively rather than
// jumping to the last hint). Idempotent: re-opening an already-open hint returns
// its text again. The response only ever contains journey.yaml hint copy, which
// by convention carries no flag values (public repo; conventions I10).
//
// Body:  none required
// Route: POST /api/users/{user}/challenges/{cid}/hints/{idx}
func (h *Handler) openHint(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	cid := r.PathValue("cid")
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdminWrite(w, r, user) {
		return
	}
	if _, ok := h.cat[cid]; !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	j, ok := h.journeys[cid]
	if !ok || len(j.Hints) == 0 {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "no hints for " + cid})
		return
	}
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil || idx < 1 || idx > len(j.Hints) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid hint index"})
		return
	}

	// Enforce in-order reveal: opening idx N requires N-1 already open.
	if idx > 1 {
		opened := make(map[int]struct{})
		for _, o := range h.store.HintViews(user)[cid] {
			opened[o] = struct{}{}
		}
		if _, prevOpen := opened[idx-1]; !prevOpen {
			httpx.WriteJSON(w, http.StatusConflict, map[string]any{
				"error": fmt.Sprintf("open hint %d before hint %d", idx-1, idx),
			})
			return
		}
	}

	at := h.now().UTC().Format(time.RFC3339Nano)
	newly, err := h.store.RecordHintView(user, cid, idx, at)
	if err != nil {
		h.logger.Error("record hint view", "err", err, "user", user, "cid", cid, "idx", idx)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not record hint view"})
		return
	}
	h.logger.Info("hint_view", "user", user, "cid", cid, "idx", idx, "newly", newly, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"user":  user,
		"cid":   cid,
		"idx":   idx,
		"hint":  j.Hints[idx-1],
		"total": len(j.Hints),
		"newly": newly,
	})
}

// --- App-H2 evade dirty-flag reset ------------------------------------------

// resetDirty is the ONLY way to clear the persistent evade dirty flag
// (store.ResetDirty) for {cid} — there is no time-based path (App-H2: waiting
// never clears it, see scoring.evaluateClean). A participant calls this after
// noticing a forbidden Falco rule fired on a run (submit will report
// EvadeForbiddenFired with the offending rule names) and redoing the attack
// cleanly. This RESTARTS the whole attempt (ADR-0003 §A2): store.ResetDirty
// also deletes the SAME (user, cid) pair's collector exfil receipt (A2-2, CEO
// enforce decision) — a RequireExfil challenge needs a brand-new exfil
// delivery after a reset, not just a clean taint, so "fire a forbidden rule →
// reset → auto-solve off the stale receipt" is not a shortcut back to solved.
//
// Idempotent: resetting an already-clean pair is a harmless no-op (200, no
// prior dirty rules). Validates the challenge exists and is evade-type (a
// dirty flag can only ever exist for an evade challenge — markDirtyOnRuleFire
// only writes for ch.Type=="evade" — so rejecting other types here is a
// guard against a confusing 200-that-does-nothing, matching /submit's own
// pre-body type guard).
//
// Auth: self-or-admin WRITE gate (selfOrAdminWrite, same as stepCheck /
// openHint) — over the auth-proxied journey/admin host a participant may
// only reset their OWN {user}'s taint; an admin may reset any.
// selfOrAdminWrite itself has a claimed-identity fallback for a header-less
// caller (see its own doc), but that fallback is UNREACHABLE for this route
// in practice: Register mounts resetDirty behind h.og (originguard.Guard),
// which 403s any request carrying neither an Origin nor a Referer header —
// exactly the shape a header-less cluster-internal caller sends — before
// selfOrAdminWrite ever runs. That is deliberate (app#124 5x review, R1
// finding C3), not an oversight: A2-2 made this endpoint able to delete
// ANOTHER participant's collector exfil receipt, and the claimed-identity
// model carries no proof the caller IS that participant, so leaving this
// route reachable without a browser-supplied Origin/Referer would turn
// A2-2's destructive reset into an unauthenticated cross-user action. Do not
// remove h.og from this route's registration, and do not add this path to
// the collector's forwarding allowlist (internal/collector/collector.go) —
// either would reopen exactly that path.
func (h *Handler) resetDirty(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	cid := r.PathValue("cid")
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdminWrite(w, r, user) {
		return
	}
	ch, ok := h.cat[cid]
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	if ch.Type != "evade" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": cid + " is not an evade challenge"})
		return
	}

	if err := h.store.ResetDirty(user, cid); err != nil {
		h.logger.Error("reset dirty", "err", err, "user", user, "cid", cid)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not reset"})
		return
	}
	h.logger.Info("dirty_reset", "user", user, "cid", cid, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user, "cid": cid, "dirty": false})
}

// --- /api/users/{user}/display-name ----------------------------------------

// setDisplayName lets a participant pick a cosmetic name shown on the
// scoreboard. Identity (`user`) stays anchored to the auth-derived slug;
// only the rendered name changes. Re-runnable any number of times.
//
// Body shape:  {"name": "Alice"}
// Constraints: 1..32 runes, no <>&"' or control chars (UI / shell safety).
//
// Auth (P18 5x): dual-path, keyed off the presence of X-Auth-Request-Email
// (selfOrAdminWrite):
//   - Over an auth-proxied ingress host (participant journey host / admin host)
//     the header is present, so the write is gated self-or-admin — a login can
//     only rename their OWN {user}, and cannot overwrite another player's name.
//   - Over the cluster-internal Service (the collector's display-name forward,
//     or a workspace pod) no header is set, so the legacy claimed-identity model
//     is preserved (isolation is NetworkPolicy's job). This keeps the
//     collector-fronted display-name flow (accepted LOW) working unchanged.
//
// Lacking cryptographic proof of identity on the internal path is intentional —
// see audit log entries for traceability.
func (h *Handler) setDisplayName(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdminWrite(w, r, user) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	name, err := validDisplayName(req.Name)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	at := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.store.SetDisplayName(user, name, at); err != nil {
		h.logger.Error("set display name", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	h.logger.Info("display_name",
		"user", user,
		"display_name", name,
		"remote_addr", r.RemoteAddr,
	)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"user":         user,
		"display_name": name,
	})
}

// --- /api/users/{user}/me ---------------------------------------------------

// userMe serves the participant self-service projection of state.
// Includes:
//   - solved challenges for this user, in solve order
//   - the next unsolved challenge id (by catalog order) so the page can
//     surface a "what to try next" link
//   - the rule fires recorded for this user in the last 60s — gives the
//     participant immediate feedback on which Falco rule they just triggered
//     without needing operator help (cuts the most common support question)
//
// Auth (P18): self-scoped participant read on the journey host. The caller may
// only read their OWN progress; selfOrAdmin derives identity from
// X-Auth-Request-Email and denies (403) mismatches and missing headers
// (fail-closed). Admins (ADMIN_EMAILS) may read any user. This replaces the
// previous "per-user progress is public" model — competition fairness (P18)
// requires that participants cannot enumerate each other's progress.
func (h *Handler) userMe(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}

	snap := h.store.Snapshot()
	ids := h.cat.IDs()
	now := h.now()

	// Catalog membership — filters out stale solves whose challenge id was
	// renamed or removed from the catalog (otherwise solved_count exceeds
	// total_challenges and the UI shows "SOLVED 15/10").
	idSet := make(map[string]struct{}, len(ids))
	for _, cid := range ids {
		idSet[cid] = struct{}{}
	}

	type solveEntry struct {
		Challenge string `json:"challenge"`
		At        string `json:"at"`
	}
	solved := make([]solveEntry, 0)
	solvedSet := make(map[string]struct{})
	for k, at := range snap.Solved {
		if k.User != user {
			continue
		}
		if _, ok := idSet[k.Challenge]; !ok {
			continue
		}
		solved = append(solved, solveEntry{Challenge: k.Challenge, At: at})
		solvedSet[k.Challenge] = struct{}{}
	}
	sort.SliceStable(solved, func(i, j int) bool { return solved[i].At < solved[j].At })

	// Next unsolved by catalog order. nil if user has solved everything.
	var nextUnsolved *string
	for _, cid := range ids {
		if _, done := solvedSet[cid]; !done {
			c := cid
			nextUnsolved = &c
			break
		}
	}

	// Last 60s of rule fires — short enough that the most recent action is
	// always at the bottom but old activity ages out quickly.
	fires := h.store.RecentRuleFires(user, float64(now.Unix()), 60)

	displayName := user
	if n, ok := snap.DisplayNames[user]; ok && n != "" {
		displayName = n
	}

	// Rank + score (P23-ME-1, CEO decision 案① 完全プライベート): computeLeaderboard
	// is the SAME full-field computation buildState (admin /api/state) uses, but
	// here we look up ONLY the caller's own row by User and read its Rank/Score —
	// every OTHER row computeLeaderboard returns is discarded right here and never
	// serialized into this response. This keeps userMe's self-scope property
	// (selfOrAdmin above already denied any {user} that is not the caller's own or
	// an admin) intact even though rank is inherently a field-relative value: the
	// computation sees everyone, but the RESPONSE never does. A user with zero
	// solves has no lbEntry in the slice (computeLeaderboard's userSet is built
	// from EventsPerUser ∪ solvers — see its doc), so rank/score naturally fall
	// back to 0 — the same "no rank yet" semantics /api/state already renders as
	// "-" for a 0-solve participant.
	rank := 0
	score := h.grader.UserScore(user, len(solved))
	for _, e := range h.computeLeaderboard(snap, ids) {
		if e.User == user {
			rank = e.Rank
			score = e.Score
			break
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":              user,
		"display_name":      displayName,
		"solved":            solved,
		"solved_count":      len(solved),
		"total_challenges":  len(ids),
		"next_unsolved":     nextUnsolved,
		"recent_rule_fires": fires,
		"events":            snap.EventsPerUser[user],
		"score":             score,
		"rank":              rank,
		// hint_penalty (#40): this projection has no single "current mission" in
		// view (unlike missionDetail's hints.penalty, which prices the specific
		// next-unopened hint for ONE mission), so it surfaces the schedule's
		// HINT1 (first-reveal) cost as a representative figure. Not used by the
		// current portal.html (which reads hints.penalty per mission instead);
		// kept for API back-compat / any external consumer of this projection.
		"hint_penalty": h.grader.HintPenaltyFor(1),
		"now":          now.UTC().Format(time.RFC3339Nano),
	})
}

// --- /api/users/{user}/journey ----------------------------------------------

// journey serves the game-style progression projection for one participant:
// the ordered mission map (solved / current / locked), the current mission's
// briefing + steps (with per-step self-check state) + progressive hints
// (opened text vs locked count), and the docs link. Progression order comes
// from the scenario (or catalog ids); "current" is the first unsolved mission
// and later missions render as locked (guided progression is the only mode).
// This is display-only — solves are never blocked here (trigger challenges
// still auto-solve via Falco).
//
// Auth (P18): this is a participant-facing read exposed on the journey host, so
// it is self-scoped — the caller may only read their OWN journey. selfOrAdmin
// derives identity from X-Auth-Request-Email and denies (403) any mismatch or a
// missing header (fail-closed). Admins (ADMIN_EMAILS) may read any user.
//
// Free mission browsing (CEO decision, P23 Story-as-docs): an optional
// `?mission=<id>` query selects which mission's `detail` block is returned,
// in place of the default "current" mission. ANY mission id present in
// `missions[]` — solved, current, OR locked — is a valid selection: brief /
// steps / Falco rule excerpt are static content, identical for every viewer,
// so letting a participant read ahead (e.g. to plan) is not a scoring
// advantage. The ONE thing that stays gated to the unlocked prefix
// (solved ∪ current) is progressive hints — see missionDetail's `hints` doc:
// a hint is a scoring lever (reveal costs points AND could let a participant
// solve a mission out of order by reading its answer-adjacent guidance before
// reaching it), so a locked mission's hints object always reports
// lockedCount == total and an empty opened list, regardless of what the
// store has recorded (defensive: the UI never offers a reveal button for a
// locked mission, but the handler does not trust the UI for this).
// An invalid/unknown `?mission=` value is ignored (falls back to `current`)
// rather than erroring — this is a display convenience, not an API contract
// participants depend on for scoring.
func (h *Handler) journey(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}
	selectedMission := strings.TrimSpace(r.URL.Query().Get("mission"))

	snap := h.store.Snapshot()
	stepChecks := h.store.StepChecks(user)
	hintViews := h.store.HintViews(user)

	// Order filtered to catalog membership (a scenario id could reference a
	// challenge that isn't loaded; skip rather than emit a phantom mission).
	order := make([]string, 0, len(h.order))
	for _, id := range h.order {
		if _, ok := h.cat[id]; ok {
			order = append(order, id)
		}
	}

	solvedSet := make(map[string]struct{})
	for k := range snap.Solved {
		if k.User != user {
			continue
		}
		if _, ok := h.cat[k.Challenge]; ok {
			solvedSet[k.Challenge] = struct{}{}
		}
	}

	// current = first unsolved mission in order; "" if all solved. Delegated
	// to scoring.CurrentMission — the SAME function scoring.Grader's
	// attempt-scope taint gate calls (ADR-0003 A1: single source of truth).
	// Reimplementing this scan independently here would let the two drift
	// apart, which is exactly the failure mode the ADR calls out.
	current := scoring.CurrentMission(order, h.cat, func(id string) bool {
		_, done := solvedSet[id]
		return done
	})

	type missionView struct {
		ID         string `json:"id"`
		Title      string `json:"title"`
		Tagline    string `json:"tagline"`
		Type       string `json:"type"`
		Status     string `json:"status"` // solved | current | locked
		HasJourney bool   `json:"hasJourney"`
		// Bridge is the mission's narrative teaser toward the next one (#47).
		// The UI shows it in the CLEARED overlay when this mission flips to
		// solved. Empty for missions without a bridge (fail-soft, display-only).
		Bridge  string `json:"bridge"`
		DocsURL string `json:"docsUrl"`
	}
	missions := make([]missionView, 0, len(order))
	// statusOf mirrors the missionView.Status computation below, keyed by id —
	// needed again after the loop to resolve the free-browsing `?mission=`
	// selection's own status (to gate its hints) without re-deriving the
	// solved/current/locked rule a second time inline.
	statusOf := make(map[string]string, len(order))
	for _, id := range order {
		j, hasJourney := h.journeys[id]
		title := id
		if hasJourney && j.Title != "" {
			title = j.Title
		}
		var status string
		switch {
		case containsKey(solvedSet, id):
			status = "solved"
		case id == current:
			status = "current"
		default:
			// Guided progression: everything after the current mission is locked.
			status = "locked"
		}
		statusOf[id] = status
		missions = append(missions, missionView{
			ID:         id,
			Title:      title,
			Tagline:    j.Tagline,
			Type:       h.cat[id].Type,
			Status:     status,
			HasJourney: hasJourney,
			Bridge:     j.Bridge,
			DocsURL:    h.docsURL(j.DocsURL),
		})
	}

	// viewMission is the mission whose detail is returned: `?mission=<id>` when
	// it names a mission actually in this run's order, else `current` (default,
	// and the fallback for an invalid/unknown query value — display
	// convenience, not an error).
	viewMission := current
	if selectedMission != "" {
		if _, ok := statusOf[selectedMission]; ok {
			viewMission = selectedMission
		}
	}

	// leadIn (#47): the narrative bridge left by the mission immediately before
	// viewMission in the progression order. Originally computed only for
	// `current` (so the "next mission" pull survives the CLEARED overlay and a
	// page reload); free mission browsing (P23) generalises this to whichever
	// mission is being viewed, so reading ahead shows the right "how did we get
	// here" narrative rather than always current's. Empty when viewMission is
	// the first mission or the previous mission has no bridge (fail-soft,
	// display-only).
	leadIn := ""
	for i, id := range order {
		if id == viewMission && i > 0 {
			leadIn = h.journeys[order[i-1]].Bridge
			break
		}
	}

	// Detail projection for the selected mission (nil when there is no mission
	// to show at all — every mission solved AND no valid ?mission= override).
	var detail any
	if viewMission != "" {
		detail = h.missionDetail(user, viewMission, statusOf[viewMission], leadIn, stepChecks[viewMission], hintViews[viewMission])
	}

	displayName := user
	if n, ok := snap.DisplayNames[user]; ok && n != "" {
		displayName = n
	}
	var currentJSON any
	if current != "" {
		currentJSON = current
	}

	// Score (#40): the Grader's arithmetic; the handler only projects it. Uses
	// the catalog-filtered solved count so score and solved_count agree.
	score := h.grader.UserScore(user, len(solvedSet))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"display_name": displayName,
		"solved_count": len(solvedSet),
		"total":        len(order),
		"current":      currentJSON,
		"missions":     missions,
		"detail":       detail,
		"score":        score,
		// hint_penalty (#40): top-level representative figure (HINT1 cost) — see
		// userMe's identical field doc. The mission-specific "cost of the NEXT
		// hint" lives in detail.hints.penalty (missionDetail), which portal.html
		// actually renders.
		"hint_penalty": h.grader.HintPenaltyFor(1),
		"now":          h.now().UTC().Format(time.RFC3339Nano),
	})
}

// docsURL absolutises a mission's relative docsUrl (e.g. "/missions/01-x/")
// against the configured docs-site origin. When no origin is set (local dev) or
// the value is empty / already absolute, it is returned unchanged. The docs live
// on a separate host (docs.<suffix>), so serving the relative path from the
// scoreboard origin would 404 — this is the fix for that (P15).
func (h *Handler) docsURL(rel string) string {
	if rel == "" || h.docsBaseURL == "" {
		return rel
	}
	if strings.HasPrefix(rel, "http://") || strings.HasPrefix(rel, "https://") {
		return rel
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return h.docsBaseURL + rel
}

// missionDetail builds a mission's detail block: briefing, per-step self-check
// state, progressive hints (opened text + locked count), and the Falco rule
// excerpt (P23 Story-as-docs). When no journey.yaml exists for the mission,
// hasJourney is false and the copy fields are empty so the UI can render
// "ブリーフィング準備中" (graceful degrade). leadIn (#47) is the previous
// mission's narrative bridge, surfaced above the briefing so the "next
// mission" pull persists past the CLEARED overlay; it is empty for the first
// mission (display-only, never affects scoring).
//
// status is the mission's projected status (solved | current | locked) —
// see journey's free-browsing doc. It gates ONLY the hints block: brief,
// steps, and the Falco rule excerpt are static content identical for every
// viewer, so they are always returned regardless of status (free browsing,
// CEO decision). Hints stay fairness-sensitive (a reveal costs points, and
// reading a locked mission's hints could let a participant skip ahead) — for
// status=="locked" this function computes the hints block WITHOUT consulting
// the store's opened set at all, always reporting the full hint count as
// locked and an empty opened list. This is enforced HERE, not left to the
// caller, so a future caller of missionDetail cannot forget the gate and leak
// hint text for a mission the participant has not reached yet.
func (h *Handler) missionDetail(user, cid, status, leadIn string, checkedSteps, openedHints []int) map[string]any {
	ch := h.cat[cid]
	j, hasJourney := h.journeys[cid]
	locked := status == "locked"

	// checkedSteps is IGNORED for a locked mission (/review-5x C2 fixup,
	// mirrors the hints gate immediately below): a locked mission's steps
	// render as a plain read-only preview, never showing tick state from the
	// store. This is the participant's own data (unlike hints there is no
	// scoring lever here — a step tick never affects the solve verdict), but
	// "locked is static display only" is the stated invariant for free
	// browsing (CEO decision), so it applies uniformly rather than carving
	// out an exception just because steps happen to be lower-stakes than hints.
	checked := make(map[int]struct{}, len(checkedSteps))
	if !locked {
		for _, i := range checkedSteps {
			checked[i] = struct{}{}
		}
	}
	type stepView struct {
		Idx     int    `json:"idx"`
		Label   string `json:"label"`
		Detail  string `json:"detail"`
		Checked bool   `json:"checked"`
	}
	steps := make([]stepView, 0, len(j.Steps))
	for i, s := range j.Steps {
		_, isChecked := checked[i]
		steps = append(steps, stepView{Idx: i, Label: s.Label, Detail: s.Detail, Checked: isChecked})
	}

	// openedHints is IGNORED for a locked mission (see doc above) — every hint
	// reports as locked, opened is always empty, regardless of what the store
	// has on file (defensive fail-closed; the UI never offers a reveal button
	// for a locked mission, but this holds even if it somehow did).
	opened := make(map[int]struct{})
	if !locked {
		for _, i := range openedHints {
			opened[i] = struct{}{}
		}
	}
	type hintView struct {
		Idx  int    `json:"idx"`
		Text string `json:"text"`
	}
	openedList := make([]hintView, 0, len(opened))
	nextHint := 0 // 1-based index of the next unopened hint; 0 = all opened OR locked
	if !locked {
		for i := 1; i <= len(j.Hints); i++ {
			if _, ok := opened[i]; ok {
				openedList = append(openedList, hintView{Idx: i, Text: j.Hints[i-1]})
			} else if nextHint == 0 {
				nextHint = i
			}
		}
	}
	// nextHint stays 0 for a locked mission (see doc above) — the UI must never
	// offer a "reveal hint N" affordance for a mission the participant has not
	// reached yet, and 0 is this projection's existing "nothing to reveal"
	// signal (the same value an all-hints-opened current mission reports).
	sort.SliceStable(openedList, func(a, b int) bool { return openedList[a].Idx < openedList[b].Idx })

	title := cid
	if hasJourney && j.Title != "" {
		title = j.Title
	}
	// exfilReceived drives the auto-solve live status in the Journey UI: once the
	// collector has *any* receipt for this (user, challenge), the UI shows
	// "collector received → waiting for a clean window → auto-clear" instead of
	// leading with the manual submit form. Read-only projection with no bearing
	// on the solve verdict (the sweeper / manual submit still gate on the exact
	// flag + clean window), so it is safe to expose without the flag value.
	requireExfil := ch.Type == "evade" && ch.RequireExfil
	exfilReceived := requireExfil && h.store.HasExfilAny(user, cid)

	// requireExpectedRuleFire / expectedRuleFired (ADR-0008): the positive-proof
	// gate's read-only projection, symmetric with requireExfil/exfilReceived
	// above. expectedRuleFired never expires and is NOT cleared by
	// reset-dirty (see internal/store's expected_rule_fire doc) — it stays
	// true forever once the participant has demonstrated the technique once,
	// across any number of subsequent resets of THIS mission's dirty taint.
	requireExpectedRuleFire := ch.Type == "evade" && ch.RequireExpectedRuleFire
	expectedRuleFired := requireExpectedRuleFire && h.store.HasExpectedRuleFire(user, cid)

	// Trigger-solve live feedback (#39): a trigger challenge auto-solves when the
	// participant's action makes Falco emit one of expectedRules. Before this the
	// Journey UI gave the participant no on-screen cue for what "success" looks
	// like — they ran a syscall in their terminal and had to guess whether it was
	// seen. Expose the success signal (expectedRules) and which of those the user
	// has ALREADY fired in a recent window (detectedRules) so the UI can render a
	// live "run the action → Falco detected it → cleared" status, mirroring the
	// exfil auto-solve flow.
	//
	// Safe to expose: expectedRules is Falco rule *names* (already public in the
	// operator /api/state challenge stats and the docs-site rule excerpts) — never
	// a flag value (conventions I10). This is a read-only projection with zero
	// bearing on the solve verdict, which stays entirely in the ingest → Grader
	// path (Grader.OnRuleFire); the UI only observes it.
	var expectedRules []string
	var detectedRules []string
	if ch.Type == "trigger" {
		expectedRules = ch.ExpectedRules
		// detectedRules = expectedRules ∩ (rule fires for this user in the recent
		// window). Delegated to the store's RecentFiresMatching so the set-intersect
		// lives in one place — the same method the evade Grader uses for its
		// forbidden-rule window (scoring.evaluateClean). This is presentational
		// only: the actual solve is recorded by ingest the instant the rule fires,
		// so a detected rule here means the mission is already (or about to be, on
		// the next 2s poll) solved. RecentFiresMatching returns a sorted set, which
		// is fine for UI display.
		detectedRules = h.store.RecentFiresMatching(
			user, expectedRules, float64(h.now().Unix()), triggerDetectWindowSeconds,
		)
	}
	// Normalise both to non-nil so they always marshal as JSON [] (never null) —
	// the Journey UI iterates them unconditionally, and the tests assert []any.
	// (evade missions leave both nil; a trigger with no expectedRules yields an
	// empty detectedRules set from RecentFiresMatching.)
	if expectedRules == nil {
		expectedRules = []string{}
	}
	if detectedRules == nil {
		detectedRules = []string{}
	}

	// falcoRule (P23 Story-as-docs): the display-only List/Macro/Rule excerpt
	// from challenges/<NN>-<slug>/rule.yaml (catalog.LoadRuleExcerpts). Static
	// content identical for every viewer — safe to return for ANY status
	// (solved/current/locked; see this function's doc), unlike hints. A
	// challenge with no rule.yaml simply yields the zero-value excerpt (three
	// non-nil empty slices), and hasFalcoRule is false so the UI can omit the
	// panel entirely rather than render three empty sections.
	falcoRule, hasFalcoRule := h.falcoRules[cid]
	if !hasFalcoRule {
		falcoRule = catalog.FalcoRuleExcerpt{
			Lists:  []catalog.FalcoListItem{},
			Macros: []catalog.FalcoMacroItem{},
			Rules:  []catalog.FalcoRuleItem{},
		}
	}

	// dirty / dirtyRules (ADR-0003 A3) REPLACE the removed windowSeconds
	// field. Only ever non-empty for an evade challenge — MarkDirty only ever
	// writes ch.Type=="evade" pairs — so a trigger/detect mission simply
	// projects dirty=false / dirtyRules=[], exactly like exfilReceived does
	// for requireExfil on a non-exfil mission. Safe to expose for ANY status
	// (solved/current/locked, unlike hints): these are Falco rule NAMES only,
	// never a flag value (conventions I10), and under the attempt-scope
	// invariant (ADR-0003 A1) a not-yet-current evade mission can never be
	// dirty, so there is nothing here a participant could read ahead of time
	// to game a later mission.
	dirtyRules := h.store.DirtyRules(user, cid)
	if dirtyRules == nil {
		dirtyRules = []string{}
	}

	return map[string]any{
		"id":                      cid,
		"status":                  status,
		"title":                   title,
		"tagline":                 j.Tagline,
		"briefing":                j.Briefing,
		"leadIn":                  leadIn,
		"type":                    ch.Type,
		"docsUrl":                 h.docsURL(j.DocsURL),
		"hasJourney":              hasJourney,
		"requireExfil":            requireExfil,
		"exfilReceived":           exfilReceived,
		"requireExpectedRuleFire": requireExpectedRuleFire,
		"expectedRuleFired":       expectedRuleFired,
		"expectedRules":           expectedRules,
		"detectedRules":           detectedRules,
		"dirty":                   len(dirtyRules) > 0,
		"dirtyRules":              dirtyRules,
		"steps":                   steps,
		"falcoRule":               falcoRule,
		"hasFalcoRule":            hasFalcoRule,
		"hints": map[string]any{
			"total":       len(j.Hints),
			"opened":      openedList,
			"lockedCount": len(j.Hints) - len(openedList),
			"nextIndex":   nextHint,
			// penalty: points forfeited for revealing the NEXT unopened hint
			// (nextHint, 1-based) — #40's per-hint-index schedule (HINT1/HINT2/
			// HINT3 cost different amounts). The Grader owns the schedule; the UI
			// shows this value on the "open hint" button so a participant makes an
			// informed reveal ("opening costs N points") for the SPECIFIC hint
			// they are about to open, not a flat figure. HintPenaltyFor(0) (when
			// nextHint is 0 — all opened, or locked per this function's doc) costs
			// nothing, matching "there is nothing left to reveal". Projection
			// only — the score arithmetic stays in the scoring layer.
			"penalty": h.grader.HintPenaltyFor(nextHint),
		},
	}
}

func containsKey(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}

// --- state ------------------------------------------------------------------

// state serves the full-event leaderboard/progress view. This is the operator
// dashboard's data source and is admin-only.
//
// Defense-in-depth (P18-1): the admin scoreboard host is already gated at
// ingress by auth-policy /check-admin, but we ALSO gate here at the app layer so
// that if the ingress host gate is ever bypassed or misrouted (e.g. the
// journey host is misconfigured to reach /api/state), a non-admin still cannot
// read the whole field's progress. Empty ADMIN_EMAILS = nobody (fail-closed),
// consistent with isAdmin. Note this does not weaken the participant journey
// host: participants use the self-scoped /api/users/{user}/{me,journey} reads,
// not /api/state.
func (h *Handler) state(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.isAdmin(r); !ok {
		h.logger.Warn("state denied: not admin", "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "admin only"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.buildState())
}

// lbEntry is one row of the full-event leaderboard computed by
// computeLeaderboard. It is intentionally package-private: buildState
// (admin-only /api/state) marshals a slice of these directly, while userMe
// (participant self-scope /api/users/{user}/me, P23-ME-1) looks up ONLY the
// caller's own entry by User and discards the rest of the slice — it never
// serializes or returns any OTHER entry. See computeLeaderboard's doc for the
// self-scope rationale.
type lbEntry struct {
	User        string `json:"user"`
	DisplayName string `json:"display_name"`
	Solved      int    `json:"solved"`
	// Score is the ranking metric (#40, CEO decision): the Grader's points
	// arithmetic (base award per solve − per-hint reveal penalty, clamped at
	// 0). Additive alongside Solved/Earliest so per-challenge progress bars
	// still read solved counts; ranking keys off Score with Earliest as the
	// tiebreak. Derived via grader.UserScore (ComputeScore single source) — no
	// inline points math here (#39 direction).
	Score    int    `json:"score"`
	Earliest string `json:"earliest"`
	Events   int    `json:"events"`
	Rank     int    `json:"rank"`
}

// computeLeaderboard is the single source of the event-wide rank/score
// ordering, shared by:
//
//   - buildState (admin-only GET /api/state — the operator dashboard's full
//     leaderboard), and
//   - userMe (participant self-scope GET /api/users/{user}/me, P23-ME-1 — the
//     portal's per-participant "Scoreboard" tab), which looks up ONLY the
//     caller's own lbEntry by User from the returned slice and discards every
//     other entry before responding. This function itself computes the FULL
//     field's standings (it has no notion of "for one caller") — the
//     self-scope narrowing happens entirely in userMe, one layer up. Do not
//     add a caller-scoped variant of this function; keep the one shared
//     computation and let each caller decide what subset of the result it is
//     allowed to expose (buildState: all of it, to admins only via isAdmin;
//     userMe: one row, to that row's own owner or an admin via selfOrAdmin).
//
// Extracted from the former buildState body verbatim (DRY, #40/#39
// continuity) — no ranking/scoring semantics changed by this refactor.
func (h *Handler) computeLeaderboard(snap store.Snapshot, ids []string) []lbEntry {
	// Catalog membership — filters out stale solves whose challenge id was
	// renamed or removed (e.g. early-prototype `01-read-shadow` still in the
	// SQLite after the 10-mission rewrite). Without this the leaderboard
	// can credit users for retired challenges and report SOLVED 15/10.
	idSet := make(map[string]struct{}, len(ids))
	for _, cid := range ids {
		idSet[cid] = struct{}{}
	}

	userSet := map[string]struct{}{}
	for u := range snap.EventsPerUser {
		userSet[u] = struct{}{}
	}
	for k := range snap.Solved {
		if _, ok := idSet[k.Challenge]; !ok {
			continue
		}
		userSet[k.User] = struct{}{}
	}
	users := make([]string, 0, len(userSet))
	for u := range userSet {
		users = append(users, u)
	}
	sort.Strings(users)

	perUserSolves := map[string][][2]string{}
	for k, at := range snap.Solved {
		if _, ok := idSet[k.Challenge]; !ok {
			continue
		}
		perUserSolves[k.User] = append(perUserSolves[k.User], [2]string{k.Challenge, at})
	}

	displayOf := func(u string) string {
		if n, ok := snap.DisplayNames[u]; ok && n != "" {
			return n
		}
		return u
	}
	leaderboard := make([]lbEntry, 0, len(users))
	for _, u := range users {
		earliest := "9999"
		for _, p := range perUserSolves[u] {
			if p[1] < earliest {
				earliest = p[1]
			}
		}
		solved := len(perUserSolves[u])
		leaderboard = append(leaderboard, lbEntry{
			User:        u,
			DisplayName: displayOf(u),
			Solved:      solved,
			// Score is the Grader's arithmetic; the handler only projects it. Pass
			// the same catalog-filtered solved count used for the Solved column so
			// the two agree, and the Grader adds the per-hint reveal penalty.
			Score:    h.grader.UserScore(u, solved),
			Earliest: earliest,
			Events:   snap.EventsPerUser[u],
		})
	}
	// Rank by Score desc (#40, CEO decision — the leaderboard order now reflects
	// the hint-penalty score, so a player who solved the same set with fewer
	// hints outranks one who leaned on hints), with Earliest solve time as the
	// tiebreak (the existing first-blood ordering, preserved for equal scores).
	sort.SliceStable(leaderboard, func(i, j int) bool {
		if leaderboard[i].Score != leaderboard[j].Score {
			return leaderboard[i].Score > leaderboard[j].Score
		}
		return leaderboard[i].Earliest < leaderboard[j].Earliest
	})
	// Rank only participants who have solved something (Solved > 0). Ranking off
	// Score would also rank a 0-solve player whose score is 0 the same as a
	// solver whose hints dragged their score to 0, so we keep the "has a solve"
	// gate: it is the has-participated signal, and a clamped-to-0 solver still
	// sorts above a 0-solve player by the Solved>0 rank assignment order (the
	// board is Score-desc then Earliest-asc, and a real solver's pre-clamp
	// standing is preserved by Earliest). Zero-solve keep Rank 0 → UI renders "-".
	rank := 0
	for i := range leaderboard {
		if leaderboard[i].Solved > 0 {
			rank++
			leaderboard[i].Rank = rank
		}
	}
	return leaderboard
}

func (h *Handler) buildState() map[string]any {
	snap := h.store.Snapshot()
	ids := h.cat.IDs()

	// Catalog membership — filters out stale solves whose challenge id was
	// renamed or removed (e.g. early-prototype `01-read-shadow` still in the
	// SQLite after the 10-mission rewrite). Without this the leaderboard
	// can credit users for retired challenges and report SOLVED 15/10.
	idSet := make(map[string]struct{}, len(ids))
	for _, cid := range ids {
		idSet[cid] = struct{}{}
	}

	leaderboard := h.computeLeaderboard(snap, ids)
	displayOf := func(u string) string {
		if n, ok := snap.DisplayNames[u]; ok && n != "" {
			return n
		}
		return u
	}

	type chSolver struct {
		User        string `json:"user"`
		DisplayName string `json:"display_name"`
		At          string `json:"at"`
	}
	type chStat struct {
		ID             string     `json:"id"`
		Type           string     `json:"type"`
		ExpectedRules  []string   `json:"expectedRules"`
		ForbiddenRules []string   `json:"forbiddenRules"`
		SolvedCount    int        `json:"solved_count"`
		Solvers        []string   `json:"solvers"`
		SolverDetails  []chSolver `json:"solver_details"` // ranked by solve time; powers the per-challenge leaderboard
		FirstSolver    *string    `json:"first_solver"`
	}
	perChalSolvers := map[string][][2]string{}
	for k, at := range snap.Solved {
		if _, ok := idSet[k.Challenge]; !ok {
			continue
		}
		perChalSolvers[k.Challenge] = append(perChalSolvers[k.Challenge], [2]string{k.User, at})
	}
	challenges := make([]chStat, 0, len(ids))
	for _, cid := range ids {
		ch := h.cat[cid]
		solvers := perChalSolvers[cid]
		sort.SliceStable(solvers, func(i, j int) bool { return solvers[i][1] < solvers[j][1] })
		names := make([]string, 0, len(solvers))
		details := make([]chSolver, 0, len(solvers))
		for _, s := range solvers {
			names = append(names, s[0])
			details = append(details, chSolver{User: s[0], DisplayName: displayOf(s[0]), At: s[1]})
		}
		var first *string
		if len(solvers) > 0 {
			first = &solvers[0][0]
		}
		expectedRules := ch.ExpectedRules
		if expectedRules == nil {
			expectedRules = []string{}
		}
		forbiddenRules := ch.ForbiddenRules
		if forbiddenRules == nil {
			forbiddenRules = []string{}
		}
		if names == nil {
			names = []string{}
		}
		challenges = append(challenges, chStat{
			ID:             cid,
			Type:           ch.Type,
			ExpectedRules:  expectedRules,
			ForbiddenRules: forbiddenRules,
			SolvedCount:    len(solvers),
			Solvers:        names,
			SolverDetails:  details,
			FirstSolver:    first,
		})
	}

	type recentEntry struct {
		User        string `json:"user"`
		DisplayName string `json:"display_name"`
		Challenge   string `json:"challenge"`
		At          string `json:"at"`
	}
	allSolves := make([]recentEntry, 0, len(snap.Solved))
	for k, at := range snap.Solved {
		if _, ok := idSet[k.Challenge]; !ok {
			continue
		}
		allSolves = append(allSolves, recentEntry{
			User:        k.User,
			DisplayName: displayOf(k.User),
			Challenge:   k.Challenge,
			At:          at,
		})
	}
	sort.SliceStable(allSolves, func(i, j int) bool { return allSolves[i].At > allSolves[j].At })
	recent := allSolves
	if len(recent) > 15 {
		recent = recent[:15]
	}

	totalEvents := 0
	for _, c := range snap.EventsPerUser {
		totalEvents += c
	}

	return map[string]any{
		"stats": map[string]any{
			// len(leaderboard) == the old len(users) (computeLeaderboard emits
			// exactly one lbEntry per participant in the field, same userSet
			// construction as before extraction — see computeLeaderboard).
			"users":      len(leaderboard),
			"challenges": len(ids),
			"solves":     len(snap.Solved),
			"events":     totalEvents,
		},
		"leaderboard":     leaderboard,
		"challenges":      challenges,
		"recent_solves":   recent,
		"solved":          allSolves, // back-compat
		"events_per_user": snap.EventsPerUser,
		"now":             h.now().UTC().Format(time.RFC3339Nano),
	}
}
