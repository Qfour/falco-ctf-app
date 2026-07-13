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
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
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

	journeys    catalog.Journeys
	order       []string
	docsBaseURL string // docs-site origin for absolutising docsUrl; "" = relative
}

func New(cat catalog.Catalog, grader *scoring.Grader, s *store.Store, logger *slog.Logger, now func() time.Time, adminEmails []string, jc JourneyConfig) *Handler {
	// /submit accepts a claimed user identity. Without per-IP throttling a
	// participant who scraped someone else's flag could brute-force submits.
	// 1 req/s with burst 10 lets legitimate typing through but blocks
	// automated flooding.
	adminSet := make(map[string]struct{}, len(adminEmails))
	for _, e := range adminEmails {
		if e = strings.TrimSpace(strings.ToLower(e)); e != "" {
			adminSet[e] = struct{}{}
		}
	}
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
	return &Handler{
		cat:                cat,
		store:              s,
		grader:             grader,
		logger:             logger,
		now:                now,
		submitLimiter:      ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
		displayNameLimiter: ratelimit.New(0.2 /* one every 5s */, 5 /* burst */).WithNow(now),
		adminSet:           adminSet,
		journeys:           journeys,
		order:              order,
		docsBaseURL:        docsBaseURL,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/state", h.state)
	mux.HandleFunc("GET /api/users/{user}/me", h.userMe)
	mux.HandleFunc("GET /api/users/{user}/journey", h.journey)
	mux.HandleFunc("POST /api/admin/reset", h.reset)
	mux.HandleFunc("POST /api/admin/users/{user}/display-name", h.adminSetDisplayName)
	mux.HandleFunc("GET /api/hints", h.hints)
	mux.HandleFunc("POST /api/admin/hints", h.releaseHint)
	submitMW := h.submitLimiter.Middleware(ratelimit.ClientIP)
	mux.Handle("POST /api/challenges/{cid}/submit", submitMW(http.HandlerFunc(h.submit)))
	// Exfil is an internal-only endpoint reached solely by the collector
	// (full one-pipe, P11.5). Workspaces cannot reach the scoreboard directly
	// once egress lockdown is on — they POST /api/challenges/{cid}/exfil to the
	// collector, which forwards to /internal/exfil here. Isolation is enforced
	// by NetworkPolicy (scoreboard ingress admits only collector); the handler
	// itself adds no auth (see recordExfil doc). Rate limiting lives on the
	// collector front, so /internal/exfil is unthrottled here.
	mux.HandleFunc("POST /internal/exfil/{cid}", h.exfilInternal)
	// Journey progression writes (self-check ticks + progressive hint reveal).
	// Rate-limited on the same bucket as /submit — participant-facing writes.
	mux.Handle("POST /api/users/{user}/challenges/{cid}/steps/{idx}/check", submitMW(http.HandlerFunc(h.stepCheck)))
	mux.Handle("POST /api/users/{user}/challenges/{cid}/hints/{idx}", submitMW(http.HandlerFunc(h.openHint)))
	dnMW := h.displayNameLimiter.Middleware(ratelimit.ClientIP)
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
// Auth: this endpoint is reached from the participant's own workspace pod
// via the cluster-internal Service. The scoreboard NetworkPolicy admits
// ctf-* namespaces for /api/users/* and /api/challenges/*; participants
// can only set their *own* display name in practice because the workspace
// shell only knows its own $FALCO_CTF_USER. Lacking cryptographic proof
// of identity is intentional — see audit log entries for traceability.
func (h *Handler) setDisplayName(w http.ResponseWriter, r *http.Request) {
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
// Auth: the endpoint is unauthenticated by design. The CTF event treats
// per-user progress as public information (the scoreboard is also public).
// If hosted behind the per-user ttyd ingress (auth-policy gated) the chart
// can rewrite /me to add the X-Auth-Request-Email check; that's an opt-in.
func (h *Handler) userMe(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if user == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user required"})
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

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":              user,
		"display_name":      displayName,
		"solved":            solved,
		"solved_count":      len(solved),
		"total_challenges":  len(ids),
		"next_unsolved":     nextUnsolved,
		"recent_rule_fires": fires,
		"events":            snap.EventsPerUser[user],
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
// Auth: same public model as /me (per-user progress is public information).
func (h *Handler) journey(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !validUser.MatchString(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
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
		DocsURL    string `json:"docsUrl"`
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
			DocsURL:    h.docsURL(j.DocsURL),
		})
	}

	// Detail projection for the current mission (nil when everything solved).
	var detail any
	if current != "" {
		detail = h.missionDetail(user, current, stepChecks[current], hintViews[current])
	}

	displayName := user
	if n, ok := snap.DisplayNames[user]; ok && n != "" {
		displayName = n
	}
	var currentJSON any
	if current != "" {
		currentJSON = current
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"display_name": displayName,
		"solved_count": len(solvedSet),
		"total":        len(order),
		"current":      currentJSON,
		"missions":     missions,
		"detail":       detail,
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
func (h *Handler) missionDetail(user, cid string, checkedSteps, openedHints []int) map[string]any {
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
	return map[string]any{
		"id":            cid,
		"title":         title,
		"tagline":       j.Tagline,
		"briefing":      j.Briefing,
		"type":          ch.Type,
		"docsUrl":       h.docsURL(j.DocsURL),
		"hasJourney":    hasJourney,
		"requireExfil":  requireExfil,
		"exfilReceived": exfilReceived,
		"windowSeconds": ch.WindowSeconds,
		"steps":         steps,
		"hints": map[string]any{
			"total":       len(j.Hints),
			"opened":      openedList,
			"lockedCount": len(j.Hints) - len(openedList),
			"nextIndex":   nextHint,
		},
	}
}

func containsKey(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}

// --- state ------------------------------------------------------------------

func (h *Handler) state(w http.ResponseWriter, _ *http.Request) {
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
		Earliest    string `json:"earliest"`
		Events      int    `json:"events"`
		Rank        int    `json:"rank"`
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
		leaderboard = append(leaderboard, lbEntry{
			User:        u,
			DisplayName: displayOf(u),
			Solved:      len(perUserSolves[u]),
			Earliest:    earliest,
			Events:      snap.EventsPerUser[u],
		})
	}
	sort.SliceStable(leaderboard, func(i, j int) bool {
		if leaderboard[i].Solved != leaderboard[j].Solved {
			return leaderboard[i].Solved > leaderboard[j].Solved
		}
		return leaderboard[i].Earliest < leaderboard[j].Earliest
	})
	// Rank only participants who have solved something; the board is already
	// sorted by Solved desc, so solvers occupy the top contiguously and get
	// ranks 1..M. Zero-solve participants keep Rank 0 → the UI renders "-".
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
