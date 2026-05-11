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
	"slices"
	"strings"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
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

func (h *Handler) receive(w http.ResponseWriter, r *http.Request) {
	var ev oapi.ReceiveFalcoEventJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		metrics.FalcoEventsReceived.WithLabelValues("decode_error").Inc()
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	var ns, pod string
	if ev.OutputFields.K8sNsName != nil {
		ns = *ev.OutputFields.K8sNsName
	}
	if ev.OutputFields.K8sPodName != nil {
		pod = *ev.OutputFields.K8sPodName
	}

	if !strings.HasPrefix(ns, "ctf-") || pod != "workspace" {
		metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "not a ctf workspace event"})
		return
	}
	user := strings.TrimPrefix(ns, "ctf-")

	recvAt := h.now().UTC().Format(time.RFC3339Nano)

	// `ev.Time` drives the rule-fire window used by evade challenges — Falco's
	// detection clock is the correct semantic there. For the visible solve
	// timestamp (`at`), prefer the receipt time so the dashboard shows
	// "just now" even when falcosidekick buffering or kernel→userspace lag
	// delays delivery.
	var tsUnix float64
	if ev.Time != nil {
		tsUnix = float64(ev.Time.Unix()) + float64(ev.Time.Nanosecond())/1e9
	}
	if tsUnix == 0 {
		tsUnix = float64(h.now().Unix())
	}

	if _, err := h.store.RecordRuleFire(user, ev.Rule, tsUnix); err != nil {
		h.logger.Error("record rule fire", "err", err)
		metrics.FalcoEventsReceived.WithLabelValues("store_error").Inc()
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	metrics.FalcoEventsReceived.WithLabelValues("accepted").Inc()

	// Trigger-type challenges: solve when expectedRules fires.
	for _, cid := range h.cat.IDs() {
		ch := h.cat[cid]
		if ch.Type != "trigger" {
			continue
		}
		if !slices.Contains(ch.ExpectedRules, ev.Rule) {
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

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accepted": true, "user": user, "rule": ev.Rule})
}
