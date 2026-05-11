// Package scoreboard wires HTTP handlers around catalog + store.
//
// Routes:
//
//	GET  /healthz                            liveness/readiness
//	POST /falco/events                       falcosidekick customWebhook
//	POST /api/challenges/{cid}/submit        evade-type flag submission
//	GET  /api/state                          dashboard JSON
//	GET  /                                   embedded HTML dashboard
package scoreboard

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

//go:embed templates/index.html
var indexHTML string

type Handler struct {
	cat    catalog.Catalog
	store  *store.Store
	logger *slog.Logger
	mux    *http.ServeMux
	dbPath string // surfaced via /healthz
	now    func() time.Time
}

type Option func(*Handler)

func WithNow(f func() time.Time) Option { return func(h *Handler) { h.now = f } }
func WithDBPath(p string) Option        { return func(h *Handler) { h.dbPath = p } }

func NewHandler(cat catalog.Catalog, s *store.Store, logger *slog.Logger, opts ...Option) *Handler {
	h := &Handler{
		cat:    cat,
		store:  s,
		logger: logger,
		mux:    http.NewServeMux(),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}
	h.mux.HandleFunc("GET /healthz", h.healthz)
	h.mux.HandleFunc("POST /falco/events", h.receiveFalco)
	h.mux.HandleFunc("POST /api/challenges/{cid}/submit", h.submit)
	h.mux.HandleFunc("GET /api/state", h.state)
	h.mux.HandleFunc("GET /", h.index)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// --- /healthz ---------------------------------------------------------------

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"challenges":    h.cat.IDs(),
		"db":            h.dbPath,
		"solved_loaded": h.store.SolvedCount(),
	})
}

// --- POST /falco/events -----------------------------------------------------

type falcoEvent struct {
	Rule         string                 `json:"rule"`
	Time         string                 `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

func (h *Handler) receiveFalco(w http.ResponseWriter, r *http.Request) {
	var ev falcoEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ns, _ := ev.OutputFields["k8s.ns.name"].(string)
	pod, _ := ev.OutputFields["k8s.pod.name"].(string)

	if !strings.HasPrefix(ns, "ctf-") || pod != "workspace" {
		writeJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "not a ctf workspace event"})
		return
	}
	user := strings.TrimPrefix(ns, "ctf-")

	recvAt := h.now().UTC().Format(time.RFC3339Nano)

	// `ev.Time` drives the rule-fire window used by evade challenges — Falco's
	// detection clock is the correct semantic there ("did a forbidden rule fire
	// in the last N seconds *of Falco time*"). For the visible solve timestamp
	// (`at`), prefer the receipt time so the dashboard shows "just now" even
	// when falcosidekick buffering or kernel→userspace lag delays delivery.
	ts := ev.Time
	if ts == "" {
		ts = recvAt
	}
	tsUnix := parseISOToUnix(ts)
	if tsUnix == 0 {
		tsUnix = float64(h.now().Unix())
	}

	if _, err := h.store.RecordRuleFire(user, ev.Rule, tsUnix); err != nil {
		h.logger.Error("record rule fire", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Trigger-type challenges: solve when expectedRules fires.
	for _, cid := range h.cat.IDs() {
		ch := h.cat[cid]
		if ch.Type != "trigger" {
			continue
		}
		if !contains(ch.ExpectedRules, ev.Rule) {
			continue
		}
		if _, err := h.store.MarkSolved(user, cid, recvAt); err != nil {
			h.logger.Error("mark solved", "err", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "user": user, "rule": ev.Rule})
}

// --- POST /api/challenges/{cid}/submit --------------------------------------

type submitReq struct {
	User string `json:"user"`
	Flag string `json:"flag"`
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	ch, ok := h.cat[cid]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"detail": "unknown challenge: " + cid})
		return
	}
	if ch.Type != "evade" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": cid + " is not an evade challenge"})
		return
	}

	var req submitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": err.Error()})
		return
	}
	user := strings.TrimSpace(req.User)
	flag := strings.TrimSpace(req.Flag)

	if user == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"detail": "user required"})
		return
	}
	if flag != ch.ExpectedFlag {
		writeJSON(w, http.StatusOK, map[string]any{"correct": false, "reason": "flag mismatch"})
		return
	}

	now := float64(h.now().Unix())
	offending := h.store.RecentForbiddenFires(user, ch.ForbiddenRules, now, ch.WindowSeconds)
	if len(offending) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{
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
	if _, err := h.store.MarkSolved(user, cid, at); err != nil {
		h.logger.Error("mark solved", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"correct": true,
		"evaded":  true,
		"solved":  true,
		"user":    user,
	})
}

// --- GET /api/state ---------------------------------------------------------

func (h *Handler) state(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.buildState())
}

// --- GET / (HTML dashboard) -------------------------------------------------

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	// `GET /` matches everything in net/http; reject any other path explicitly.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// --- helpers ----------------------------------------------------------------

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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		// Best-effort; client may have hung up.
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// parseISOToUnix accepts the falcosidekick `time` field (RFC3339 with optional
// fractional seconds and trailing Z). Returns 0 on parse failure — the caller
// substitutes "now" in that case (matching Python behavior).
func parseISOToUnix(ts string) float64 {
	if ts == "" {
		return 0
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000Z", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return float64(t.Unix()) + float64(t.Nanosecond())/1e9
		}
	}
	return 0
}
