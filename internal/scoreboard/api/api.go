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
	"sort"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type Handler struct {
	cat            catalog.Catalog
	store          *store.Store
	logger         *slog.Logger
	now            func() time.Time
	submitLimiter  *ratelimit.Limiter
}

func New(cat catalog.Catalog, s *store.Store, logger *slog.Logger, now func() time.Time) *Handler {
	// /submit accepts a claimed user identity. Without per-IP throttling a
	// participant who scraped someone else's flag could brute-force submits.
	// 1 req/s with burst 10 lets legitimate typing through but blocks
	// automated flooding.
	return &Handler{
		cat:           cat,
		store:         s,
		logger:        logger,
		now:           now,
		submitLimiter: ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/state", h.state)
	submitMW := h.submitLimiter.Middleware(ratelimit.ClientIP)
	mux.Handle("POST /api/challenges/{cid}/submit", submitMW(http.HandlerFunc(h.submit)))
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
	auditLog("solved", "user", user, "newly", newly)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"correct": true,
		"evaded":  true,
		"solved":  true,
		"user":    user,
	})
}

// --- state ------------------------------------------------------------------

func (h *Handler) state(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.buildState())
}

func (h *Handler) buildState() map[string]any {
	snap := h.store.Snapshot()
	ids := h.cat.IDs()

	userSet := map[string]struct{}{}
	for u := range snap.EventsPerUser {
		userSet[u] = struct{}{}
	}
	for k := range snap.Solved {
		userSet[k.User] = struct{}{}
	}
	users := make([]string, 0, len(userSet))
	for u := range userSet {
		users = append(users, u)
	}
	sort.Strings(users)

	perUserSolves := map[string][][2]string{}
	for k, at := range snap.Solved {
		perUserSolves[k.User] = append(perUserSolves[k.User], [2]string{k.Challenge, at})
	}

	type lbEntry struct {
		User     string `json:"user"`
		Solved   int    `json:"solved"`
		Earliest string `json:"earliest"`
		Events   int    `json:"events"`
		Rank     int    `json:"rank"`
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
			User:     u,
			Solved:   len(perUserSolves[u]),
			Earliest: earliest,
			Events:   snap.EventsPerUser[u],
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

	type chStat struct {
		ID             string   `json:"id"`
		Type           string   `json:"type"`
		ExpectedRules  []string `json:"expectedRules"`
		ForbiddenRules []string `json:"forbiddenRules"`
		SolvedCount    int      `json:"solved_count"`
		Solvers        []string `json:"solvers"`
		FirstSolver    *string  `json:"first_solver"`
	}
	perChalSolvers := map[string][][2]string{}
	for k, at := range snap.Solved {
		perChalSolvers[k.Challenge] = append(perChalSolvers[k.Challenge], [2]string{k.User, at})
	}
	challenges := make([]chStat, 0, len(ids))
	for _, cid := range ids {
		ch := h.cat[cid]
		solvers := perChalSolvers[cid]
		sort.SliceStable(solvers, func(i, j int) bool { return solvers[i][1] < solvers[j][1] })
		names := make([]string, 0, len(solvers))
		for _, s := range solvers {
			names = append(names, s[0])
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
			FirstSolver:    first,
		})
	}

	type recentEntry struct {
		User      string `json:"user"`
		Challenge string `json:"challenge"`
		At        string `json:"at"`
	}
	allSolves := make([]recentEntry, 0, len(snap.Solved))
	for k, at := range snap.Solved {
		allSolves = append(allSolves, recentEntry{User: k.User, Challenge: k.Challenge, At: at})
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

