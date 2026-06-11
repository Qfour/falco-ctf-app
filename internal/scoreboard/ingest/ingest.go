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
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

type Handler struct {
	cat     catalog.Catalog
	store   *store.Store
	logger  *slog.Logger
	now     func() time.Time
	limiter *ratelimit.Limiter
}

func New(cat catalog.Catalog, s *store.Store, logger *slog.Logger, now func() time.Time) *Handler {
	// Per-source-IP token bucket. /falco/events is a high-volume internal
	// endpoint (falcosidekick batches events); rate is generous so a busy
	// CTF doesn't get throttled while still capping pathological bursts.
	return &Handler{
		cat:     cat,
		store:   s,
		logger:  logger,
		now:     now,
		limiter: ratelimit.New(100 /* req/s */, 200 /* burst */).WithNow(now),
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mw := h.limiter.Middleware(ratelimit.ClientIP)
	mux.Handle("POST /falco/events", mw(http.HandlerFunc(h.receive)))
}

// incomingEvent extends the OpenAPI-generated FalcoEvent with `priority`,
// which falcosidekick sends at the top level but isn't in our minimal spec.
// `container.image.repository` is read separately from OutputFields'
// AdditionalProperties below.
type incomingEvent struct {
	OutputFields oapi.FalcoEvent_OutputFields `json:"output_fields"`
	Rule         string                       `json:"rule"`
	Time         *time.Time                   `json:"time,omitempty"`
	Priority     *string                      `json:"priority,omitempty"`
}

func (h *Handler) receive(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var ev incomingEvent
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

	// Defense-in-depth alongside the cluster-internal NetworkPolicy on
	// /falco/events: even if a forged request reaches this handler, the
	// container.image.repository field is part of the Falco event Falco itself
	// produces; an attacker would need to set this in the forged JSON, but
	// adding the explicit check makes the contract from AGENTS.md actionable.
	imageRepo, _ := ev.OutputFields.AdditionalProperties["container.image.repository"].(string)
	// Accept both `falco-ctf/challenge` (preferred, e.g. ghcr) and
	// `falco-ctf-challenge` (e.g. ECR cached path after retag) since the
	// substring choice depends on the registry's repo-naming conventions.
	if !strings.Contains(imageRepo, "falco-ctf/challenge") && !strings.Contains(imageRepo, "falco-ctf-challenge") {
		metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "not a challenge container"})
		return
	}

	// Reject events explicitly tagged below Notice. Unknown / missing priority
	// passes through so older falcosidekick / Falco versions stay compatible.
	if ev.Priority != nil {
		switch strings.ToLower(*ev.Priority) {
		case "debug", "informational", "info":
			metrics.FalcoEventsReceived.WithLabelValues("ignored").Inc()
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"ignored": true, "reason": "below minimum priority"})
			return
		}
	}

	user := strings.TrimPrefix(ns, "ctf-")

	// Rule-fire timestamp uses server-side now() rather than the
	// attacker-controlled ev.Time. ev.Time is retained as a log field for
	// observability (e.g. measuring Falco→scoreboard delivery latency) but
	// must not drive evade-window decisions: a forged request setting `time`
	// to the distant past could bury a forbidden fire outside the window.
	recvNow := h.now()
	tsUnix := float64(recvNow.UnixNano()) / 1e9

	if _, err := h.store.RecordRuleFire(user, ev.Rule, tsUnix); err != nil {
		h.logger.Error("record rule fire", "err", err)
		metrics.FalcoEventsReceived.WithLabelValues("store_error").Inc()
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	metrics.FalcoEventsReceived.WithLabelValues("accepted").Inc()

	recvAt := recvNow.UTC().Format(time.RFC3339Nano)

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
