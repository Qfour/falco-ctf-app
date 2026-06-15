// Package api serves the read-side JSON state view and the flag-submission
// endpoint for evade-type challenges.
//
//	GET  /api/state
//	POST /api/challenges/{cid}/submit
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
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

type Handler struct {
	cat                catalog.Catalog
	store              *store.Store
	logger             *slog.Logger
	now                func() time.Time
	submitLimiter      *ratelimit.Limiter
	displayNameLimiter *ratelimit.Limiter
	adminSet           map[string]struct{}
}

func New(cat catalog.Catalog, s *store.Store, logger *slog.Logger, now func() time.Time, adminEmails []string) *Handler {
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
	return &Handler{
		cat:                cat,
		store:              s,
		logger:             logger,
		now:                now,
		submitLimiter:      ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
		displayNameLimiter: ratelimit.New(0.2 /* one every 5s */, 5 /* burst */).WithNow(now),
		adminSet:           adminSet,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/state", h.state)
	mux.HandleFunc("GET /api/users/{user}/me", h.userMe)
	mux.HandleFunc("POST /api/admin/reset", h.reset)
	mux.HandleFunc("POST /api/admin/users/{user}/display-name", h.adminSetDisplayName)
	mux.HandleFunc("GET /api/hints", h.hints)
	mux.HandleFunc("POST /api/admin/hints", h.releaseHint)
	submitMW := h.submitLimiter.Middleware(ratelimit.ClientIP)
	mux.Handle("POST /api/challenges/{cid}/submit", submitMW(http.HandlerFunc(h.submit)))
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

	ch, ok := h.cat[cid]
	if !ok {
		metrics.SubmissionsTotal.WithLabelValues(cid, "unknown_challenge").Inc()
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "unknown challenge: " + cid})
		return
	}
	if ch.Type != "evade" {
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
	if flag != ch.ExpectedFlag {
		metrics.SubmissionsTotal.WithLabelValues(cid, "wrong_flag").Inc()
		auditLog("wrong_flag", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"correct": false, "reason": "flag mismatch"})
		return
	}

	now := float64(h.now().Unix())
	offending := h.store.RecentForbiddenFires(user, ch.ForbiddenRules, now, ch.WindowSeconds)
	if len(offending) > 0 {
		metrics.SubmissionsTotal.WithLabelValues(cid, "not_evaded").Inc()
		auditLog("not_evaded", "user", user, "offending_rules", offending)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"correct": true,
			"evaded":  false,
			"reason": fmt.Sprintf(
				"flag is correct, but the forbidden rule(s) %v fired in the last %ds for user %q. "+
					"Try again — wait %ds, then submit.",
				offending, ch.WindowSeconds, user, ch.WindowSeconds,
			),
		})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	newly, err := h.store.MarkSolved(user, cid, at)
	if err != nil {
		h.logger.Error("mark solved", "err", err)
	}
	if newly {
		metrics.SolvesTotal.WithLabelValues(cid, "evade").Inc()
	}
	metrics.SubmissionsTotal.WithLabelValues(cid, "solved").Inc()
	auditLog("solved", "user", user, "newly", newly, "display_name", h.store.DisplayName(user))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"correct":      true,
		"evaded":       true,
		"solved":       true,
		"user":         user,
		"display_name": h.store.DisplayName(user),
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

// --- state ------------------------------------------------------------------

func (h *Handler) state(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.buildState())
}

func (h *Handler) buildState() map[string]any {
	snap := h.store.Snapshot()
	ids := h.cat.IDs()

	// Catalog membership — filters out stale solves whose challenge id was
	// renamed or removed (e.g. early-prototype `01-read-shadow` still in the
	// SQLite after the NimbusBreach rewrite). Without this the leaderboard
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
	for i := range leaderboard {
		leaderboard[i].Rank = i + 1
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

