// Package ingest handles the falcosidekick customWebhook intake path.
//
//	POST /falco/events
//
// Filters events to the `ctf-<username>/workspace` namespace+pod pair,
// records rule fires for evade windowing, and marks trigger-type
// challenges solved.
package ingest

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type Handler struct {
	cat    catalog.Catalog
	store  *store.Store
	logger *slog.Logger
	now    func() time.Time
}

func New(cat catalog.Catalog, s *store.Store, logger *slog.Logger, now func() time.Time) *Handler {
	return &Handler{cat: cat, store: s, logger: logger, now: now}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /falco/events", h.receive)
}

type event struct {
	Rule         string                 `json:"rule"`
	Time         string                 `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

func (h *Handler) receive(w http.ResponseWriter, r *http.Request) {
	var ev event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		metrics.FalcoEventsReceived.WithLabelValues("decode_error").Inc()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ns, _ := ev.OutputFields["k8s.ns.name"].(string)
	pod, _ := ev.OutputFields["k8s.pod.name"].(string)

	if !strings.HasPrefix(ns, "ctf-") || pod != "workspace" {
		metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
		writeJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "not a ctf workspace event"})
		return
	}
	user := strings.TrimPrefix(ns, "ctf-")

	recvAt := h.now().UTC().Format(time.RFC3339Nano)

	// `ev.Time` drives the rule-fire window used by evade challenges — Falco's
	// detection clock is the correct semantic there. For the visible solve
	// timestamp (`at`), prefer the receipt time so the dashboard shows
	// "just now" even when falcosidekick buffering or kernel→userspace lag
	// delays delivery.
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
		metrics.FalcoEventsReceived.WithLabelValues("store_error").Inc()
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	metrics.FalcoEventsReceived.WithLabelValues("accepted").Inc()

	// Trigger-type challenges: solve when expectedRules fires.
	for _, cid := range h.cat.IDs() {
		ch := h.cat[cid]
		if ch.Type != "trigger" {
			continue
		}
		if !contains(ch.ExpectedRules, ev.Rule) {
			continue
		}
		newly, err := h.store.MarkSolved(user, cid, recvAt)
		if err != nil {
			h.logger.Error("mark solved", "err", err)
			continue
		}
		if newly {
			metrics.SolvesTotal.WithLabelValues(cid, "trigger").Inc()
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "user": user, "rule": ev.Rule})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// parseISOToUnix accepts the falcosidekick `time` field (RFC3339 with
// optional fractional seconds and trailing Z). Returns 0 on parse failure
// — the caller substitutes "now".
func parseISOToUnix(ts string) float64 {
	if ts == "" {
		return 0
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000000Z",
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, ts); err == nil {
			return float64(t.Unix()) + float64(t.Nanosecond())/1e9
		}
	}
	return 0
}
