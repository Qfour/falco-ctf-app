// Package identityobs is the one observation point for "this request was
// refused (or, for the portal, served an empty shell) because the caller has no
// usable proven identity" (app#404, ADR-0038).
//
// Four gates feed it, each calling Observer.Record (or one of the shorthands
// below) at the moment it refuses:
//
//   - strict:        ratelimit.MiddlewareStrict (identity-keyed buckets), through
//     the observer it is handed at assembly time;
//   - self_or_admin: api.selfOrAdmin;
//   - authenticated: api.requireAuthenticated / api.boardIdentity;
//   - portal:        GET /portal, which answers 200 with an empty shell.
//
// A refusal is counted once, by the gate that refused it, in
// scoreboard_identity_denials_total{gate, reason}, and sampled into one Warn
// line per (gate, reason) per 10 seconds. The metric is the contract with
// platform (conventions, "identity 拒否の観測"); the log is a pointer to it.
//
// Dependency direction (ADR-0038 D3, C6 (a)): collector links
// internal/scoreboard/ratelimit and COPYs it by name into its image, but is not
// given this package. So ratelimit must NOT import identityobs (the import would
// compile on the host and break only the collector image build, which is not a
// required check); it takes a func(*http.Request) from its caller instead, and
// this package imports ratelimit for the header name — which makes the reverse
// import a cycle the compiler rejects. TestCollectorClosureExcludesIdentityobs
// is the second tripwire.
package identityobs

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
)

// Gate is which identity gate refused the request. A closed set: the label
// values of the metric, and the sampling key of the log.
type Gate string

const (
	// GateStrict is the identity-keyed rate-limit bucket's fail-closed front
	// (ratelimit.MiddlewareStrict): no header, or a blank one, is 403 before any
	// token is spent.
	GateStrict Gate = "strict"
	// GateSelfOrAdmin is api.selfOrAdmin: the {user}-scoped reads (me, journey)
	// and the participant POSTs. It is named for the Authz class, not "read":
	// it also guards writes.
	GateSelfOrAdmin Gate = "self_or_admin"
	// GateAuthenticated is api.requireAuthenticated / boardIdentity: any proven
	// identity, no {user} to match (the board routes).
	GateAuthenticated Gate = "authenticated"
	// GatePortal is GET /portal. It does not refuse (the shell is public by
	// design); it counts a shell served to a caller with no usable identity,
	// which on a fresh page load is the only signal there is (ADR-0038 C2).
	GatePortal Gate = "portal"
)

// Reason is why the identity was unusable. A closed set.
type Reason string

const (
	// ReasonNoIdentity: X-Auth-Request-Email is absent or blank. absent versus
	// blank is a log field only (header), never a label value.
	ReasonNoIdentity Reason = "no_identity"
	// ReasonNonCanonical: the header is there, but it is neither the canonical
	// <seat>@<EXPECTED_EMAIL_DOMAIN> nor an ADMIN_EMAILS member (the latter only
	// where the gate admits admins). The cause is configuration (an
	// EXPECTED_EMAIL_DOMAIN mismatch, or auth-policy not stamping the canonical
	// form: I8), so a healthy production has 0 of these.
	ReasonNonCanonical Reason = "non_canonical"
	// ReasonMismatch: a canonical identity for a different seat
	// (self_or_admin only). A participant's own action (editing the URL), so it
	// does not stay 0 and is not part of the alert.
	ReasonMismatch Reason = "mismatch"
)

// Pair is one declared (gate, reason) combination.
type Pair struct {
	Gate   Gate
	Reason Reason
}

// declared is the closed set of series that exist from process start, each at
// 0 (so the first denial is an increase() from an existing 0, and a missing
// series means "this binary does not export the metric", never "no denial yet").
// strict x non_canonical is absent on purpose: strict only asks whether the
// identity is non-empty; the gate behind it makes the canonical judgement.
var declared = []Pair{
	{GateStrict, ReasonNoIdentity},
	{GateSelfOrAdmin, ReasonNoIdentity},
	{GateSelfOrAdmin, ReasonNonCanonical},
	{GateSelfOrAdmin, ReasonMismatch},
	{GateAuthenticated, ReasonNoIdentity},
	{GateAuthenticated, ReasonNonCanonical},
	{GatePortal, ReasonNoIdentity},
	{GatePortal, ReasonNonCanonical},
}

// Declared returns a copy of the declared (gate, reason) pairs.
func Declared() []Pair { return append([]Pair(nil), declared...) }

func isDeclared(p Pair) bool {
	for _, d := range declared {
		if d == p {
			return true
		}
	}
	return false
}

// DenialsTotal is scoreboard_identity_denials_total. Counted once per request,
// by the gate that refused it: strict refuses before the handler runs, so a
// request is never also counted by self_or_admin. No bucket, route or user
// label (metrics.go's rule: nothing per-participant; per-route 403s are in
// scoreboard_http_request_duration_seconds). Process-global like every other
// metric here; tests assert deltas.
var DenialsTotal = newDenialsTotal()

func newDenialsTotal() *prometheus.CounterVec {
	v := promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "scoreboard",
		Subsystem: "identity",
		Name:      "denials_total",
		Help: "Requests an identity gate refused for lack of a usable proven identity, by gate and reason. " +
			"gate=portal counts portal shells served without a usable identity (the identity panes stay empty). " +
			"In healthy production reason=no_identity and reason=non_canonical stay 0.",
	}, []string{"gate", "reason"})
	for _, p := range declared {
		v.WithLabelValues(string(p.Gate), string(p.Reason))
	}
	return v
}

// logInterval is the spacing of the log line per (gate, reason). The metric
// counts every denial; the log points at it, so an anonymous flood (or a
// header-less tab polling every 2 seconds) cannot flood the Recreate-lost pod
// log. The key set is the 8 declared pairs, so the ceiling is 0.8 lines/second
// whatever the traffic.
const logInterval = 10 * time.Second

// logMsg is constant: the reason is a field, so JSON logs filter on it. It is
// not auth-policy's "identity denied" (a different event: a roster refusal).
const logMsg = "identity gate denied"

// header states, the value of the log's "header" field.
const (
	headerAbsent  = "absent"
	headerBlank   = "blank"
	headerPresent = "present"
)

type sampleState struct {
	last       time.Time // when a line was last emitted for this pair
	suppressed int       // denials swallowed since then
}

// Observer counts and logs denials. The zero value is usable (slog.Default()
// and time.Now at use time), and so is a nil *Observer (it records through a
// shared zero one): a handler assembled without New still counts and logs. It
// holds only the sampling state; the metric is package-level, so any number of
// Observers (the api handler's and the view handler's) feed the same series.
type Observer struct {
	logger *slog.Logger
	now    func() time.Time

	// mu guards state. Kept off any limiter's lock, so a 403 flood never
	// contends with Allow on the token buckets.
	mu    sync.Mutex
	state map[Pair]*sampleState
}

// fallback serves a nil *Observer.
var fallback Observer

// New returns an Observer that logs to logger (nil = slog.Default() when a
// line is written) and samples on now (nil = time.Now).
func New(logger *slog.Logger, now func() time.Time) *Observer {
	return &Observer{logger: logger, now: now}
}

// Record counts one denial by gate for reason and writes the sampled log line.
// The gate decides the reason; this only records it. An undeclared pair is a
// programming error and panics, like a wrong label count on the metric would:
// the tests (every gate, every reason) are what catch it, and nothing outside
// the 8 declared pairs may become a series or a sampling key.
func (o *Observer) Record(r *http.Request, gate Gate, reason Reason) {
	if o == nil {
		o = &fallback
	}
	p := Pair{gate, reason}
	if !isDeclared(p) {
		panic(fmt.Sprintf("identityobs: undeclared (gate, reason) = (%q, %q)", gate, reason))
	}
	DenialsTotal.WithLabelValues(string(gate), string(reason)).Inc()
	o.log(r, p)
}

// StrictNoIdentity is the observer ratelimit.MiddlewareStrict is handed: a
// header that is absent or blank at the strict gate.
func (o *Observer) StrictNoIdentity(r *http.Request) {
	o.Record(r, GateStrict, ReasonNoIdentity)
}

// Portal records a portal shell served to a caller who is neither an admin nor
// a canonical seat. The reason follows the header: absent or blank is
// no_identity; anything else is non_canonical. The response stays a 200.
func (o *Observer) Portal(r *http.Request) {
	reason := ReasonNonCanonical
	if headerState(r) != headerPresent {
		reason = ReasonNoIdentity
	}
	o.Record(r, GatePortal, reason)
}

// headerState reports whether X-Auth-Request-Email is absent, blank (only
// whitespace in the value the gates read) or present. Never the value itself.
func headerState(r *http.Request) string {
	vals := r.Header.Values(ratelimit.IdentityHeader)
	switch {
	case len(vals) == 0:
		return headerAbsent
	case strings.TrimSpace(r.Header.Get(ratelimit.IdentityHeader)) == "":
		return headerBlank
	default:
		return headerPresent
	}
}

// log writes the sampled Warn line. The first denial per pair logs at once;
// the next ones inside logInterval are only counted and reported as
// `suppressed` on the following line.
//
// Exactly six fields, all fixed vocabulary: gate, reason, route (the mux
// PATTERN, not the path: the path carries a participant's name), remote_addr
// (the TCP peer, no port; XFF and CF-Connecting-IP are something a participant
// can influence, so they are not used), header (absent|blank|present) and
// suppressed. Never logged: the identity value, the URL path or its parameters,
// the query. In particular a mismatch does not name the caller (ADR-0038
// Consequences: attribution is given up, the metric says "it is happening").
func (o *Observer) log(r *http.Request, p Pair) {
	now := time.Now
	if o.now != nil {
		now = o.now
	}
	t := now()

	o.mu.Lock()
	if o.state == nil {
		o.state = make(map[Pair]*sampleState, len(declared))
	}
	st, ok := o.state[p]
	if !ok {
		st = &sampleState{}
		o.state[p] = st
	} else if t.Sub(st.last) < logInterval {
		st.suppressed++
		o.mu.Unlock()
		return
	}
	suppressed := st.suppressed
	st.last, st.suppressed = t, 0
	o.mu.Unlock()

	route := r.Pattern
	if route == "" {
		route = "-"
	}
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn(logMsg,
		"gate", string(p.Gate), "reason", string(p.Reason),
		"route", route, "remote_addr", remote,
		"header", headerState(r), "suppressed", suppressed)
}
