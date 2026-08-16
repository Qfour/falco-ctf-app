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
//	POST /api/users/{user}/display-name
//	GET  /api/hints
//	POST /api/admin/hints
//	POST /api/admin/reset
//	POST /api/admin/users/{user}/display-name
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

	"github.com/Qfour/falco-ctf-app/internal/catalog"
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
// is owned entirely by the ingest → Grader.EvaluateTrigger path and is
// independent of this window (a rule fire records the solve the instant it
// arrives, regardless of what this projection shows). It is deliberately the
// same 60s window /me uses for its rule-fire feed so the two agree on screen.
// Signpost: if a future grader ever gains a windowed trigger verdict, this
// value and the grader's window should be sourced from one place.
const triggerDetectWindowSeconds = 60

// JourneyConfig carries the /journey UI inputs into the api handler:
// narrative content, the mission progression order, and the docs-site origin.
// All are optional — the handler applies safe defaults (see New).
type JourneyConfig struct {
	Journeys catalog.Journeys // challengeId -> narrative content (may be nil)
	Order    []string         // mission sequence (scenario order or catalog ids)
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
func New(cat catalog.Catalog, grader *scoring.Grader, s *store.Store, logger *slog.Logger, now func() time.Time, adminEmails []string, allowedOrigins []string, jc JourneyConfig, dc DetectConfig) *Handler {
	// /submit accepts a claimed user identity. Without per-IP throttling a
	// participant who scraped someone else's flag could brute-force submits.
	// 1 req/s with burst 10 lets legitimate typing through but blocks
	// automated flooding.
	adminSet := newAdminSet(adminEmails)
	journeys := jc.Journeys
	if journeys == nil {
		journeys = catalog.Journeys{}
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
		order:              order,
		docsBaseURL:        docsBaseURL,
		detectRunner:       dc.Runner,
		detectInflight:     inflight,
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

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/state", h.state)
	mux.HandleFunc("GET /api/users/{user}/me", h.userMe)
	mux.HandleFunc("GET /api/users/{user}/journey", h.journey)
	mux.Handle("POST /api/admin/reset", h.og(http.HandlerFunc(h.reset)))
	mux.Handle("POST /api/admin/users/{user}/display-name", h.og(http.HandlerFunc(h.adminSetDisplayName)))
	mux.HandleFunc("GET /api/hints", h.hints)
	mux.Handle("POST /api/admin/hints", h.og(http.HandlerFunc(h.releaseHint)))
	submitMW := h.submitLimiter.Middleware(ratelimit.ClientIP)
	// NOT wrapped by the origin guard (P23-2 follow-up). This route has TWO
	// callers: the journey UI (browser fetch, carries Origin) AND the
	// collector's verbatim forward of the participant's curl submission
	// (internal/collector/collector.go — "Routes fronted"; curl sends no
	// Origin/Referer at all). Egress lockdown makes the collector-forwarded
	// curl path the PRIMARY flag-submission route once a workspace can no
	// longer reach the scoreboard directly, so a fail-closed Origin gate here
	// would 403 every legitimate submission via that path and break scoring —
	// exactly the class of regression this middleware must never cause. The
	// CSRF this would otherwise mitigate (an attacker riding a victim's
	// session to submit — and thereby credit — a flag the attacker chose) has
	// no destructive blast radius comparable to /api/admin/reset (the
	// mitigation's actual target): at most it credits a solve, it does not
	// delete state or read another user's data. Accepted residual risk;
	// revisit only if submit ever gains a destructive side effect.
	mux.Handle("POST /api/challenges/{cid}/submit", submitMW(http.HandlerFunc(h.submit)))
	// Detect grading reuses the SAME per-IP submit limiter (same trust model as
	// /submit) plus a global in-flight cap enforced inside the handler (429 past
	// it, never queued). Unlike /submit above, this route has only ONE caller:
	// the journey UI's browser fetch (the "Grade" button on a detect mission's
	// condition textarea — docs/detect-challenge-design.md §6). The collector's
	// forward allowlist (internal/collector/collector.go — "Routes fronted")
	// does NOT include submit-detect, so there is no server-to-server curl
	// caller to protect against a fail-closed gate here — same reasoning as
	// steps/{idx}/check and hints/{idx} below. Origin-guarded.
	mux.Handle("POST /api/challenges/{cid}/submit-detect", h.og(submitMW(http.HandlerFunc(h.submitDetect))))
	// Exfil is an internal-only endpoint reached solely by the collector
	// (full one-pipe, P11.5). Workspaces cannot reach the scoreboard directly
	// once egress lockdown is on — they POST /api/challenges/{cid}/exfil to the
	// collector, which forwards to /internal/exfil here. Isolation is enforced
	// by NetworkPolicy (scoreboard ingress admits only collector); the handler
	// itself adds no auth (see recordExfil doc). Rate limiting lives on the
	// collector front, so /internal/exfil is unthrottled here. It is also
	// DELIBERATELY NOT wrapped by the origin guard (P23-2): this is a
	// server-to-server request with no browser Origin/Referer, so gating it
	// would 403 every legitimate exfil receipt and silently break the boss
	// capstone's scoring path.
	mux.HandleFunc("POST /internal/exfil/{cid}", h.exfilInternal)
	// Journey progression writes (self-check ticks + progressive hint reveal).
	// Rate-limited on the same bucket as /submit — participant-facing writes.
	// These two ARE origin-guarded: unlike submit/display-name below, they are
	// reached ONLY from the portal's Journey pane browser fetch
	// (templates/portal.html) — the collector's forward allowlist
	// (internal/collector/collector.go) does not
	// include steps/{idx}/check or hints/{idx} — so there is no server-to-server
	// caller to protect against a fail-closed gate here.
	mux.Handle("POST /api/users/{user}/challenges/{cid}/steps/{idx}/check", h.og(submitMW(http.HandlerFunc(h.stepCheck))))
	mux.Handle("POST /api/users/{user}/challenges/{cid}/hints/{idx}", h.og(submitMW(http.HandlerFunc(h.openHint))))
	dnMW := h.displayNameLimiter.Middleware(ratelimit.ClientIP)
	// NOT wrapped by the origin guard (P23-2 follow-up). Unlike submit above,
	// this route has only ONE caller: the collector's verbatim forward
	// (internal/collector/collector.go — "Routes fronted") of the
	// participant's curl-issued display-name update. No browser template in
	// this repo fetches this participant-facing path directly (the journey UI
	// has no such call; the only browser caller of a display-name endpoint is
	// index.html's ADMIN /api/admin/users/{user}/display-name, a distinct
	// route that stays origin-guarded above). A fail-closed gate here would
	// therefore 403 every legitimate call with no browser-CSRF surface to
	// protect in exchange.
	mux.Handle("POST /api/users/{user}/display-name", dnMW(http.HandlerFunc(h.setDisplayName)))
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
	ch := h.cat[cid]
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
			"reason": fmt.Sprintf(
				"flag is correct, but the forbidden rule(s) %v fired in the last %ds for user %q. "+
					"Try again — wait %ds, then submit.",
				outcome.Offending, ch.WindowSeconds, user, ch.WindowSeconds,
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
		"note":     "collector received the data. Now submit the flag (a clean 30s window is still required).",
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

	// Score (#40) is the Grader's arithmetic — the handler only projects it. We
	// pass the catalog-filtered solved count (the same value shown as
	// solved_count) so score and solved_count are derived from one number; the
	// Grader adds the per-hint reveal penalty from the store.
	score := h.grader.UserScore(user, len(solved))
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
		"hint_penalty":      h.grader.Points().HintPenalty,
		"now":               now.UTC().Format(time.RFC3339Nano),
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
func (h *Handler) journey(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}

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

	// current = first unsolved mission in order; "" if all solved.
	current := ""
	for _, id := range order {
		if _, done := solvedSet[id]; !done {
			current = id
			break
		}
	}

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

	// leadIn (#47): the narrative bridge left by the mission immediately before
	// `current` in the progression order. It persists on the current-mission
	// detail so the "next mission" pull survives the (transient) CLEARED overlay
	// and a page reload. Empty when current is the first mission or the previous
	// mission has no bridge (fail-soft, display-only).
	leadIn := ""
	if current != "" {
		for i, id := range order {
			if id == current && i > 0 {
				leadIn = h.journeys[order[i-1]].Bridge
				break
			}
		}
	}

	// Detail projection for the current mission (nil when everything solved).
	var detail any
	if current != "" {
		detail = h.missionDetail(user, current, leadIn, stepChecks[current], hintViews[current])
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
		"hint_penalty": h.grader.Points().HintPenalty,
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

// missionDetail builds the current-mission detail block: briefing, per-step
// self-check state, and progressive hints (opened text + locked count). When no
// journey.yaml exists for the mission, hasJourney is false and the copy fields
// are empty so the UI can render "ブリーフィング準備中" (graceful degrade).
// leadIn (#47) is the previous mission's narrative bridge, surfaced above the
// briefing so the "next mission" pull persists past the CLEARED overlay; it is
// empty for the first mission (display-only, never affects scoring).
func (h *Handler) missionDetail(user, cid, leadIn string, checkedSteps, openedHints []int) map[string]any {
	ch := h.cat[cid]
	j, hasJourney := h.journeys[cid]

	checked := make(map[int]struct{}, len(checkedSteps))
	for _, i := range checkedSteps {
		checked[i] = struct{}{}
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

	opened := make(map[int]struct{}, len(openedHints))
	for _, i := range openedHints {
		opened[i] = struct{}{}
	}
	type hintView struct {
		Idx  int    `json:"idx"`
		Text string `json:"text"`
	}
	openedList := make([]hintView, 0, len(opened))
	nextHint := 0 // 1-based index of the next unopened hint; 0 = all opened
	for i := 1; i <= len(j.Hints); i++ {
		if _, ok := opened[i]; ok {
			openedList = append(openedList, hintView{Idx: i, Text: j.Hints[i-1]})
		} else if nextHint == 0 {
			nextHint = i
		}
	}
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
	// path (EvaluateTrigger); the UI only observes it.
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

	return map[string]any{
		"id":            cid,
		"title":         title,
		"tagline":       j.Tagline,
		"briefing":      j.Briefing,
		"leadIn":        leadIn,
		"type":          ch.Type,
		"docsUrl":       h.docsURL(j.DocsURL),
		"hasJourney":    hasJourney,
		"requireExfil":  requireExfil,
		"exfilReceived": exfilReceived,
		"expectedRules": expectedRules,
		"detectedRules": detectedRules,
		"windowSeconds": ch.WindowSeconds,
		"steps":         steps,
		"hints": map[string]any{
			"total":       len(j.Hints),
			"opened":      openedList,
			"lockedCount": len(j.Hints) - len(openedList),
			"nextIndex":   nextHint,
			// penalty: points forfeited per hint reveal (#40). The Grader owns the
			// value; the UI shows it on the "open hint" button so a participant
			// makes an informed reveal ("opening costs N points"). Projection only —
			// the score arithmetic stays in the scoring layer.
			"penalty": h.grader.Points().HintPenalty,
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
			"users":      len(users),
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
