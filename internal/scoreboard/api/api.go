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
//	POST /api/users/{user}/profile
//	POST /api/admin/reset
//	POST /api/admin/users/{user}/display-name
//	POST /api/admin/users/{user}/profile-reset
//	GET  /api/board/threads
//	GET  /api/board/threads/{tid}
//	POST /api/board/threads
//	POST /api/board/threads/{tid}/messages
//	POST /api/board/threads/{tid}/like
//	POST /api/board/threads/{tid}/unlike
//	GET  /api/admin/board/threads
//	GET  /api/admin/board/threads/{tid}
//	POST /api/admin/board/threads/{tid}/reply
//	POST /api/admin/board/threads/{tid}/state
//	POST /api/admin/board/messages/{mid}/state
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Qfour/falco-ctf-app/internal/apispec"
	"github.com/Qfour/falco-ctf-app/internal/board"
	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/challengeid"
	"github.com/Qfour/falco-ctf-app/internal/identity"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/detect"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/httpx"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/identityobs"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/metrics"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/oapi"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/originguard"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/ratelimit"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/scoring"
	"github.com/Qfour/falco-ctf-app/internal/store"
)

// unknownCIDLabel is the single metric-label / log value every cid that is not
// a catalog key is folded into, so the label set stays the closed catalog. It is
// challengeid.Unknown, which is outside the challenge-id grammar.
//
// The grammar of a {cid} path segment is challengeid.Valid (app#437: the one
// definition catalog.Load, the flags file, the collector and the generators share).
// It is checked before any catalog lookup so an id outside the grammar is never
// used as a metric label, logged, or reflected in a response.
const unknownCIDLabel = challengeid.Unknown

// challenge resolves a {cid} path value once, at the top of a handler. It
// checks the grammar first, then the catalog. It returns the catalog entry,
// the value to use for every metric label and audit-log field that carries the
// id (cid itself when it is a catalog key, unknownCIDLabel otherwise), and
// whether the id was found. A cid outside the grammar is simply "not found".
//
// The rule for handlers: a cid that is not in the catalog (or is outside the
// grammar) is folded into unknownCIDLabel before it is used for anything; the
// raw cid is only used after a successful lookup, where it is a catalog key.
// A static test (cid_label_static_test.go) keeps the raw value out of
// WithLabelValues.
func (h *Handler) challenge(cid string) (ch catalog.Challenge, label string, ok bool) {
	if !challengeid.Valid(cid) {
		return catalog.Challenge{}, unknownCIDLabel, false
	}
	ch, ok = h.cat[cid]
	if !ok {
		return catalog.Challenge{}, unknownCIDLabel, false
	}
	return ch, cid, true
}

// invalidDisplayName rejects characters that would break either UI
// rendering (HTML metachars) or shell display (control chars), plus the
// bidi controls, zero-width characters (Cf) and C1 controls (app#331). This
// is NOT an anti-impersonation control: other invisible or blank-looking
// characters still pass (Lo U+3164 / U+115F / U+1160 / U+FFA0, So U+2800, Mn
// U+034F / U+FE00-FE0F / U+E0100-E01EF / U+180B-180D), and duplicate names are
// allowed, so one seat can still be made to look like another's.
//
//   - \p{Cc}: the C0 controls (U+0000-001F), DEL (U+007F) AND the C1 controls
//     (U+0080-009F, e.g. U+0085 NEL). The old class stopped at U+007F.
//   - \p{Cf}: format characters — U+200B ZERO WIDTH SPACE, U+202E RIGHT-TO-LEFT
//     OVERRIDE and the other bidi controls, U+2060 WORD JOINER, U+FEFF BOM,
//     U+00AD SOFT HYPHEN, the tag characters, ... The display name rule is
//     Cc ∪ Cf (ADR-0039). hintleak moved to sourcehygiene.Hidden in ADR-0043, so
//     the two no longer match (intentional).
//
// One exception is carved out in displayNameHasForbidden (not here — a regexp
// cannot look at neighbours): U+200D ZERO WIDTH JOINER between two emoji,
// because that is what makes a ZWJ emoji sequence such as the "woman
// technologist" one render as a single glyph. A 32-rune max keeps leaderboard
// columns predictable.
//
// The Cc + Cf half is written once (forbiddenInvisible) and shared with
// invalidInlineText.
var invalidDisplayName = regexp.MustCompile(`[<>&"'` + forbiddenInvisible + `]`)

// forbiddenInvisible is the Cc + Cf half of the display-name class, as regexp
// class members; invalidDisplayName adds the metacharacters.
const forbiddenInvisible = `\p{Cc}\p{Cf}`

// invalidInlineText is the class for text a participant writes that is rendered
// INLINE next to other text (the board's thread subject, app#377): Cc + Cf, with
// no HTML metacharacters (prose keeps ' " & < >; output escaping covers them).
var invalidInlineText = regexp.MustCompile(`[` + forbiddenInvisible + `]`)

// flagShapePattern is app#292 Phase 2's fairness gate: it matches the
// SHAPE of a flag (`FALCO{...}`), never a specific value — every free-text
// board write (thread creation's subject AND body, a participant's own
// follow-up, an admin reply) is rejected 400 if it matches this, regardless
// of whether the braces contain a real, in-play flag (security+qa review,
// app#292 Phase 3: the subject check was missing from Phase 2 — a public
// audience=all thread's subject is rendered to every participant exactly
// like its body, so it needed the same gate). This is deliberately NOT a
// comparison against any actual challenge flag: comparing against real
// values would require the board to know every challenge's expectedFlag
// (a scope leak this package's board handlers must not have — board.Store
// is physically isolated from internal/store/scoring, see internal/board's
// package doc), and would let a participant probe "is THIS specific string
// the flag" via the board's 400/200 response — an oracle strictly worse
// than blanket-rejecting the shape. Blanket rejection also catches an
// HONEST mistake (a participant pasting what they believe is a flag while
// asking for help) just as well as a deliberate leak attempt — the
// fairness property this gate protects ("no participant's flag becomes
// visible to another participant via the board") does not care about
// intent. The empty-brace shape (FALCO with a bare "{}" pair) is still rejected;
// bare "FALCO" with no braces at all is NOT (a participant should still be
// able to say "I'm on the FALCO mission" in a support thread).
//
// Consumers: the board's subject and body (board.go), and a display name
// (validDisplayName, app#402; its shape rows are in display-name-parity/cases.yaml).
var flagShapePattern = regexp.MustCompile(`FALCO\{[^}]*\}`)

// Stable, non-leaking response-body text (Issue #113). Never put err.Error()
// from a JSON decode or a store/SQLite call into a response body — the
// decoder can name internal struct fields and the store can surface driver
// text, schema names, or file paths. Log the real err via h.logger next to
// the WriteJSON call; the body always gets one of these constants instead.
// Named (not inlined) so a future RFC 9457 problem+json contract (pending
// ADR) can carry the same string into a machine-checked field without a
// second wording change.
const (
	errMsgInvalidBody          = "invalid request body"
	errMsgUnknownChallenge     = "unknown challenge"
	errMsgResetFailed          = "could not reset scoreboard"
	errMsgSetDisplayNameFailed = "could not set display name"
	// errMsgFlagShapeRejected is flagShapePattern's stable, non-leaking
	// rejection text — deliberately does not echo back the offending text
	// (which would just re-display the very value being rejected).
	errMsgFlagShapeRejected = "message body must not contain a flag-shaped value"
	// errMsgDisplayNameFlagShape is the same gate for a display name (app#402): a
	// participant's name is shown next to their posts on the public board (audience=all
	// threads) and on the operator's screens, so it must not be a way around the
	// subject / body gate. Fixed text, never the input.
	errMsgDisplayNameFlagShape = "display name must not contain a flag-shaped value"
	// Board-specific stable, non-leaking text (Issue #113's discipline,
	// applied to app#292 Phase 2 — see the const block above this one for
	// the full rationale).
	errMsgBoardListFailed     = "could not list board threads"
	errMsgBoardCreateFailed   = "could not create board thread"
	errMsgBoardGetFailed      = "could not load board thread"
	errMsgBoardAppendFailed   = "could not append board message"
	errMsgBoardReplyFailed    = "could not reply to board thread"
	errMsgBoardLikeFailed     = "could not like board thread"
	errMsgBoardUnlikeFailed   = "could not unlike board thread"
	errMsgBoardStateFailed    = "could not update board moderation state"
	errMsgBoardThreadNotFound = "thread not found"
	errMsgBoardMsgNotFound    = "message not found"
	errMsgBoardSelfLike       = "cannot like your own thread"
	// errMsgBoardInvalidState mirrors internal/board.ErrInvalidState's text
	// (a stable, self-crafted sentinel message — not a driver/schema leak —
	// but restated as its own constant here rather than returning
	// err.Error() directly, so this package's error bodies stay drawn from
	// ONE local, grep-able set, matching every other handler in this file).
	errMsgBoardInvalidState = `state must be "visible", "hidden", or "deleted"`
)

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

// actionBucket is the ratelimit.IdentityRequestsTotal "bucket" label of
// Handler.actionLimiter (steps/check + hints/{idx} + reset-dirty + profile). Keep it a
// fixed constant: it is a metric label.
const actionBucket = "participant_action"

// detectBucket is the same label for Handler.detectLimiter (submit-detect
// only, app#328). Separate from actionBucket so a burst of grader submissions
// (each one a replay Job) cannot 429 a participant's hint open or step tick.
const detectBucket = "detect"

// boardPostBucket / boardLikeBucket are the same label for
// Handler.boardPostLimiter (thread creation + follow-up messages) and
// Handler.boardLikeLimiter (like + unlike), strict since app#397.
const (
	boardPostBucket = "board_post"
	boardLikeBucket = "board_like"
)

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
	// it for ANY mission, whatever its status, carries no fairness
	// risk. (Hints are not status-gated either since ADR-0027: they are a
	// function of what the participant has opened; see missionDetail.)
	FalcoRules catalog.FalcoRuleExcerpts
	Order      []string // mission sequence (scenario order or catalog ids)
	// DocsBaseURL is the participant docs-site origin (e.g. https://docs.<suffix>).
	// When non-empty, each mission's relative docsUrl is rewritten to an absolute
	// URL under this origin. Empty = keep the relative path.
	DocsBaseURL string
}

type Handler struct {
	cat    catalog.Catalog
	store  *store.Store
	grader *scoring.Grader
	logger *slog.Logger
	now    func() time.Time
	// denials is the one observation point for identity refusals (app#404,
	// ADR-0038): selfOrAdmin, requireAuthenticated / boardIdentity and the strict
	// middlewares all record here, and only here.
	denials       *identityobs.Observer
	submitLimiter *ratelimit.Limiter
	// actionLimiter is the IDENTITY-keyed bucket (app#315, ADR-0027
	// Consequences, ADR-0032 D3) shared by the browser-only participant
	// actions: steps/check, hints/{idx}, reset-dirty. Deliberately NOT
	// submitLimiter: that one is keyed by client IP, and under a venue NAT
	// every participant shares one IP, so one person's hint opens could 429
	// someone else's submit (solve time is a tie-break). A future ADR-0032
	// attempt route joins this bucket via actionMW. POST /api/users/{user}/profile
	// (ADR-0034 D8) joins it too.
	actionLimiter *ratelimit.Limiter
	// detectLimiter is submit-detect's own IDENTITY-keyed bucket (app#328):
	// same shape as actionLimiter (1 req/s, burst 10) but a separate token
	// map, so grading does not spend the hint/step/reset budget.
	detectLimiter *ratelimit.Limiter
	adminSet      map[string]struct{}
	// emailDomain is IdentityConfig.ExpectedEmailDomain (lower-cased, trimmed).
	// Read-only after New.
	emailDomain string
	// hiddenSet is the HIDDEN_USERS allowlist (CEO/ops request: a venue-demo
	// account, e.g. test1, must be free to solve challenges and trip Falco
	// rules without its score/solve state appearing on the PUBLIC leaderboard
	// participants see). Applied ONLY inside computeLeaderboard's userSet
	// construction — every other read (userMe's own row, /api/state's
	// per-challenge solver lists, recent-solve feed) is untouched, so a hidden
	// user's own self-view (GET /api/users/{user}/me) still works exactly as
	// before; only their appearance in the RANKED FIELD is suppressed. Empty
	// (default) = nobody hidden (I7: environment-agnostic default).
	hiddenSet   map[string]struct{}
	originGuard *originguard.Guard

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
	detectRunner scoring.DetectRunner
	// gradeDetect is grader.SubmitDetect. A field only so a test can make the
	// Grader's second seat gate answer ErrInvalidUser for a body user the handler's
	// own gate accepted (app#479): over real HTTP that branch is unreachable.
	gradeDetect    func(ctx context.Context, runner scoring.DetectRunner, user, cid, condition string) (scoring.DetectOutcome, error)
	detectInflight chan struct{}
	// gradeEvade / recordExfil are grader.SubmitEvade / grader.RecordExfil, fields
	// for the same reason as gradeDetect (app#486): submit's and exfilInternal's own
	// identity.ValidSeat answers first, so their mapping of the Grader's second seat
	// gate is unreachable over real HTTP and a test needs a fake to hold it.
	gradeEvade  func(user, cid, flag string) (scoring.EvadeOutcome, error)
	recordExfil func(user, cid, flag string) (scoring.ExfilStatus, error)

	// board is the QA Board store (app#292 — destination model, supersedes
	// P25's per-user QA ticket chat wholesale as of Phase 2). nil is possible
	// only in tests that never wire BoardConfig — cmd/scoreboard/main.go
	// always opens one, unconditionally (there is no "board disabled"
	// feature flag, unlike DetectConfig's Runner). Every board route handler
	// is reached only after a gate (requireAuthenticated/isAdmin) has
	// already run, so a nil board here would only ever be dereferenced by a
	// legitimately-authorized caller in a misconfigured deployment —
	// acceptable because that is exactly the shape of every other
	// required-but-unwired dependency in this Handler (e.g. a nil store
	// would panic just as readily).
	board *board.Store
	// boardPostLimiter / boardLikeLimiter are the two identity-keyed rate
	// buckets app#292 Phase 2 requires (separate from each other):
	// boardPostLimiter covers thread creation + follow-up messages,
	// boardLikeLimiter covers like/unlike. Both are participant-only —
	// admin board writes (reply/state) are never rate-limited, matching
	// P25's own admin-write precedent (adminReply/adminReset/etc., all
	// RateLimit: "none").
	boardPostLimiter *ratelimit.Limiter
	boardLikeLimiter *ratelimit.Limiter
}

// BoardConfig carries the QA Board store (app#292) into the api handler. A
// separate config struct (matching JourneyConfig/DetectConfig's shape)
// rather than a bare *board.Store parameter, so New's signature reads the
// same way for every optional subsystem this Handler wires.
type BoardConfig struct {
	Store *board.Store
}

// IdentityConfig carries the I8 identity contract (ADR-0034 D5) into the api
// handler. ExpectedEmailDomain is EXPECTED_EMAIL_DOMAIN, the same value
// auth-policy spells the canonical identity with: after auth-policy the only
// identity a participant request can carry is `<seat>@<ExpectedEmailDomain>`,
// so "self" is exact equality with `<user>@<ExpectedEmailDomain>`. EMPTY means
// no email can ever be a participant's own (every self check is false and
// UsernameFromEmail yields ""): fail-closed, never "any domain".
type IdentityConfig struct {
	ExpectedEmailDomain string
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
// hard cap (rejected past it with 429, never queued) plus the identity-keyed
// detect bucket (detectMW, burst 10, 1 req/s per identity) keeps a flood from
// spawning unbounded work (design §3.3). The cap is shared by every identity;
// a per-identity concurrency limit is tracked in #341 (do not enable
// DETECT_RUNNER=k8s for an event before it lands).
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
//
// hiddenUsers is the HIDDEN_USERS allowlist (comma-separated scoreboard
// USERNAMES, not emails — unlike adminEmails/allowedOrigins, this is matched
// against the store's user key directly, so it needs no email-domain
// stripping). Empty = nobody hidden.
func New(cat catalog.Catalog, grader *scoring.Grader, s *store.Store, logger *slog.Logger, now func() time.Time, adminEmails []string, allowedOrigins []string, hiddenUsers []string, jc JourneyConfig, dc DetectConfig, bc BoardConfig, ic IdentityConfig) *Handler {
	// /submit accepts a claimed user identity. Without per-IP throttling a
	// participant who scraped someone else's flag could brute-force submits.
	// 1 req/s with burst 10 lets legitimate typing through but blocks
	// automated flooding.
	adminSet := newAdminSet(adminEmails)
	hiddenSet := newHiddenSet(hiddenUsers)
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
		cat:            cat,
		store:          s,
		grader:         grader,
		gradeDetect:    grader.SubmitDetect,
		gradeEvade:     grader.SubmitEvade,
		recordExfil:    grader.RecordExfil,
		logger:         logger,
		now:            now,
		denials:        identityobs.New(logger, now),
		submitLimiter:  ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
		actionLimiter:  ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
		detectLimiter:  ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
		adminSet:       adminSet,
		emailDomain:    strings.ToLower(strings.TrimSpace(ic.ExpectedEmailDomain)),
		hiddenSet:      hiddenSet,
		originGuard:    originguard.New(allowedOrigins, logger),
		journeys:       journeys,
		falcoRules:     falcoRules,
		order:          order,
		docsBaseURL:    docsBaseURL,
		detectRunner:   dc.Runner,
		detectInflight: inflight,
		board:          bc.Store,
		// app#292 Phase 2: 10s/1 refill, burst 3 — shared by thread creation
		// and follow-up messages (identity-keyed, MiddlewareStrict), so
		// a spammer cannot dodge the bucket by spreading posts across many
		// thread ids. Mirrors P25's old questionLimiter rate exactly.
		boardPostLimiter: ratelimit.New(0.1 /* one every 10s */, 3 /* burst */).WithNow(now),
		// Likes are lower-stakes and clicked more casually than a written
		// post, so this bucket is looser — 1/s refill, burst 10 (matches
		// submitLimiter's shape), still identity-keyed and separate from the
		// post bucket so a burst of likes can never starve a participant's
		// ability to open a thread or reply.
		boardLikeLimiter: ratelimit.New(1 /* req/s */, 10 /* burst */).WithNow(now),
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

// newHiddenSet normalises the HIDDEN_USERS allowlist into a lookup set
// (trimmed, lower-cased, blanks dropped — usernames are already
// lower-case-only per identity.SeatPattern, but normalising defensively costs nothing
// and matches newAdminSet's shape). Empty input = empty set = nobody hidden.
func newHiddenSet(hiddenUsers []string) map[string]struct{} {
	set := make(map[string]struct{}, len(hiddenUsers))
	for _, u := range hiddenUsers {
		if u = strings.TrimSpace(strings.ToLower(u)); u != "" {
			set[u] = struct{}{}
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

// UsernameFromEmail returns the seat in a canonical identity: email must be
// exactly `<seat>@<domain>` (already lower-cased by the caller) with seat a valid
// username slug. It returns "" for anything else — in particular for ANY other
// domain, and always when domain is empty (fail-closed). This is the one place
// the canonical form is parsed; selfOrAdmin's equality check and the portal's
// display hint both go through the same exact comparison.
func UsernameFromEmail(email, domain string) string {
	if email == "" || domain == "" {
		return ""
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || email[at+1:] != domain {
		return ""
	}
	user := email[:at]
	if !identity.ValidSeat(user) {
		return ""
	}
	return user
}

// NewUsernameDeriver returns the function the portal shell and the board use to
// turn a request into the display-only username slug (ADR-0034 D5; the former
// package-level DeriveUsername). It reads X-Auth-Request-Email and accepts ONLY
// the canonical `<seat>@<expectedEmailDomain>`: an email on any other domain, or
// any email when expectedEmailDomain is empty, derives "" — so `alice@evil` can
// never become the author "alice".
//
// It is a UI convenience and a board author key, never an authorization
// decision: every read/write the Journey/Me panes make is independently
// re-checked by selfOrAdmin against the SAME header. A caller
// cannot use it to see another user's data — it only returns the caller's OWN
// local part. It does not know what a seat is: it returns the local part of
// any `<slug>@<expectedEmailDomain>`, so an ADMIN_EMAILS member on that domain
// (e.g. admin@ctf.local with expectedEmailDomain ctf.local) derives "admin",
// and one on another reserved domain derives "". That is display-only; whether
// the caller may do anything is isAdmin / selfOrAdmin, never this.
func NewUsernameDeriver(expectedEmailDomain string) func(*http.Request) string {
	domain := strings.ToLower(strings.TrimSpace(expectedEmailDomain))
	return func(r *http.Request) string {
		return UsernameFromEmail(strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email"))), domain)
	}
}

// og wraps a handler with the origin guard (P23-2). Applied to browser-only
// state-changing routes. NOT applied to routes that are also (or solely)
// reached via the collector's server-to-server forward — see each route's
// own comment below for why it is excluded (POST /internal/exfil/{cid},
// POST /api/challenges/{cid}/submit).
func (h *Handler) og(next http.Handler) http.Handler {
	return h.originGuard.Middleware(next)
}

// Routes returns the api package's declarative route table (ADR-0005 V2) —
// the single artifact scoreboard.Handler's NewHandler feeds into
// apispec.NewMux, and (via that same call's return value) what the parity
// tests (internal/scoreboard's *_test.go) compare against
// docs/openapi-scoreboard.yaml. Every route's OriginGuarded /
// CollectorForward value below is repeated, unchanged, from the per-route
// comments that used to live only beside the old mux.Handle calls; see
// og's doc for the general shape of the asymmetry and each entry below for
// the route-specific reasoning.
//
// This package deliberately has no Register(mux)/NewMux method of its own
// (LOW, 5x review: one used to exist here, calling apispec.Register(mux,
// h.Routes()) directly, but nothing in this codebase — production or test —
// ever called it; scoreboard.Handler's NewHandler always collects every
// sub-package's Routes() into one table and calls apispec.NewMux exactly
// once). A
// second, unused registration entry point contradicted I14's "single
// registration path" claim on its face, even though it happened to be dead;
// it was removed rather than documented as test-only, since it had no test
// either.
func (h *Handler) Routes() []apispec.Route {
	// ADR-0023 V5 caller label (ratelimit.ClientIPKeyed): this route family
	// IS Cloudflare-fronted (unlike ingest's /falco/events, see
	// that package's ClientIPKeyed call), so a sustained non-cf_connecting_ip
	// clientIPSource rate under this label is the ADR-0023 Signpost 2 drift
	// signal — see internal/scoreboard/ratelimit/metrics.go's doc.
	submitMW := h.submitLimiter.Middleware(ratelimit.ClientIPKeyed("submit"))
	// app#315: identity-keyed, FAIL-CLOSED (MiddlewareStrict: no proven
	// identity header -> 403 without consuming a token, never "unlimited" and
	// never an IP fallback). Order on the wire is og -> actionMW -> handler
	// (selfOrAdmin): the origin guard still rejects the header-less curl
	// shape first, and this closes the remaining hole — a header-less caller
	// carrying a spoofed allowed Origin must not reach a handler on a route
	// that is browser-only by design. The handlers behind actionMW use
	// selfOrAdmin (header REQUIRED) and their Authz is declared
	// self-or-admin accordingly; actionMW is a second layer, not the only one.
	// app#328 moved submit-detect (the route that attaches a SOLVE) onto the
	// same gate with its OWN bucket (detectMW), so it is header-REQUIRED too.
	actionMW := h.actionLimiter.MiddlewareStrict(actionBucket, ratelimit.IdentityKeyed, h.denials.StrictNoIdentity)
	detectMW := h.detectLimiter.MiddlewareStrict(detectBucket, ratelimit.IdentityKeyed, h.denials.StrictNoIdentity)
	// app#292 Phase 2 / app#397: identity-keyed and FAIL-CLOSED, the same
	// MiddlewareStrict shape as actionMW/detectMW. A board thread/message is
	// attributed to the caller's OWN proven identity, so the bucket tracks that
	// identity, never the NAT/proxy IP a whole classroom shares. A header-less
	// (or blank) request is the limiter's 403 and spends no token; before
	// app#397 these two buckets fell back to an "ip:"+ClientIP key, which let a
	// header-less request spend a token and, past the IP key's burst, answer
	// 429 instead of 403. Every board route also runs requireAuthenticated
	// (header REQUIRED), so no legitimate caller is affected.
	boardPostMW := h.boardPostLimiter.MiddlewareStrict(boardPostBucket, ratelimit.IdentityKeyed, h.denials.StrictNoIdentity)
	boardLikeMW := h.boardLikeLimiter.MiddlewareStrict(boardLikeBucket, ratelimit.IdentityKeyed, h.denials.StrictNoIdentity)
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
			// why it stays origin-guarded. (The participant-facing
			// POST /api/users/{user}/display-name route was removed in ADR-0034
			// S1: a participant now sets display name + avatar through the
			// authenticated profile route, not a collector forward.)
			Method: "POST", Pattern: "/api/admin/users/{user}/display-name",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.adminSetDisplayName)),
		},
		{
			// ADR-0034 D8: the operator's take-back for an inappropriate name or
			// avatar (and the deletion-request path, D11). Same posture as the
			// admin display-name route: the dashboard (browser) is the caller, so
			// it is origin-guarded; never collector-forwarded.
			Method: "POST", Pattern: "/api/admin/users/{user}/profile-reset",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.adminResetProfile)),
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
			RateLimit: "per-IP 1 req/s burst 10",
			Handler:   submitMW(http.HandlerFunc(h.submit)),
		},
		{
			// Detect grading is rate-limited on its own identity-keyed bucket
			// (app#328; it used to share /submit's per-IP bucket, and is kept
			// apart from the hint/step/reset bucket) plus a global
			// in-flight cap enforced inside the handler (429 past it, never
			// queued). Unlike /submit above, this route has NO caller today (no detect
			// challenge ships yet). The planned caller is the portal's Grade
			// button on a detect mission's condition textarea
			// (docs/detect-challenge-design.md §6); it does not ship before the
			// P14-C revisit (REFACTORING 2026-08-31 "not doing"). The
			// browser-only premise below is about that planned caller.
			// The collector's forward allowlist (internal/collector/collector.go
			// — "Routes fronted") does NOT include submit-detect, so there is no
			// server-to-server curl caller to protect against a fail-closed gate
			// here — same reasoning as steps/{idx}/check and hints/{idx} below.
			// Origin-guarded, then detectMW (no identity header -> 403, no token
			// consumed), then submitDetect's selfOrAdmin (identity header
			// REQUIRED, app#346). Do NOT add this path to the collector's forward
			// allowlist.
			Method: "POST", Pattern: "/api/challenges/{cid}/submit-detect",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (own bucket, separate from steps/check, hints, reset-dirty, profile and submit) + global in-flight grader cap (5)",
			Handler:   h.og(detectMW(http.HandlerFunc(h.submitDetect))),
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
			//
			// The ingress admin catch-all still routes /internal/exfil/ here for
			// an admin BROWSER (oauth2-proxy stamps X-Auth-Request-Email on it),
			// so exfilInternal itself closes that path: any X-Auth-Request-* header
			// => 403, body not application/json => 415. The collector adds no such
			// header, so the legitimate caller is unaffected. Authz is therefore the
			// internal-only claimed-identity class (same as display-name).
			Method: "POST", Pattern: "/internal/exfil/{cid}",
			Audience: apispec.AudienceInternal, Authz: apispec.AuthzInternalClaimedIdentity,
			OriginGuarded: false, CollectorForward: true,
			RateLimit: "none (the limit lives on the collector front)",
			Handler:   http.HandlerFunc(h.exfilInternal),
		},
		{
			// Journey progression writes (self-check ticks). Rate-limited on the
			// identity-keyed action bucket (app#315) — NOT /submit's per-IP
			// bucket, so a NAT'd venue's tick/hint traffic cannot 429 a solve.
			// This IS
			// origin-guarded: unlike submit below, it is reached
			// ONLY from the portal's Journey pane browser fetch
			// (templates/portal.html) — the collector's forward allowlist
			// (internal/collector/collector.go) does not include
			// steps/{idx}/check — so there is no server-to-server caller to
			// protect against a fail-closed gate here.
			Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/steps/{idx}/check",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (shared by steps/check, hints, reset-dirty, profile; separate from submit and submit-detect)",
			Handler:   h.og(actionMW(http.HandlerFunc(h.stepCheck))),
		},
		{
			// Progressive hint reveal — same reasoning as steps/check above, plus
			// a second one: the 409/200 distinction is a cross-user oracle if an
			// unauthenticated caller can drive it.
			Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/hints/{idx}",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (shared by steps/check, hints, reset-dirty, profile; separate from submit and submit-detect)",
			Handler:   h.og(actionMW(http.HandlerFunc(h.openHint))),
		},
		{
			// App-H2: the explicit, self-scoped escape hatch from the persistent
			// evade dirty flag (internal/store MarkDirty/DirtyRules). Same trust
			// model and route family as steps/check and hints/{idx} above —
			// reached ONLY from the portal's Journey pane browser fetch, never
			// from the collector's forward allowlist — so it is origin-guarded
			// and gated by selfOrAdmin (header required) the same way.
			//
			// Do NOT remove the origin guard from this route and do NOT add it
			// to the collector's forward allowlist: ADR-0003 A2-2 made this
			// endpoint able to delete another participant's exfil receipt, and
			// a header-less cluster-internal caller would carry no proof it IS
			// {user}. selfOrAdmin, which this route runs, 403s it (the dual-path
			// self-or-admin-write gate that used to let it through was removed,
			// app#346). The guard 403s exactly the
			// shape a header-less cluster-internal caller sends, BEFORE the
			// self-or-admin check runs — that is what keeps A2-2's destructive
			// reset from becoming an unauthenticated cross-user action (app#124
			// 5x, R1 C3). This is also why ADR-0005 V4 asserts, as a dedicated
			// check (not just a bijection count), that reset-dirty never appears
			// in the collector-forward set.
			Method: "POST", Pattern: "/api/users/{user}/challenges/{cid}/reset-dirty",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (shared by steps/check, hints, reset-dirty, profile; separate from submit and submit-detect)",
			Handler:   h.og(actionMW(http.HandlerFunc(h.resetDirty))),
		},
		{
			// ADR-0034 D8: the participant's own profile (display name + one
			// prepared avatar id). Browser-only like steps/check: origin-guarded,
			// NOT in the collector's forward allowlist, and gated by selfOrAdmin
			// (identity header REQUIRED): a header-less claimed-identity allow
			// would let a cluster-internal caller write someone else's profile.
			// actionMW is the identity-keyed fail-closed
			// bucket (a header-less request is 403 before it touches a bucket).
			Method: "POST", Pattern: "/api/users/{user}/profile",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzSelfOrAdmin,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (shared by steps/check, hints, reset-dirty, profile; separate from submit and submit-detect)",
			Handler:   h.og(actionMW(http.HandlerFunc(h.setProfile))),
		},
		{
			// app#292 Phase 2: the participant's own visible board listing —
			// every audience='all' thread PLUS the caller's own
			// audience='admin' threads, never anyone else's. Reads are never
			// origin-guarded or rate-limited (same posture as the other
			// self-scoped reads above — /me, /journey, and P25's old
			// listQuestions before it).
			Method: "GET", Pattern: "/api/board/threads",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzAuthenticated,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.boardListThreads),
		},
		{
			// One thread, full messages. board.Store.GetThread performs the
			// audience/ownership/moderation-state entitlement check inside the
			// SAME call as the read (no separate "check" round trip) — an
			// unknown id, a wrong-audience id, and a moderated-away id are all
			// the SAME 404 to a non-admin caller (no existence oracle).
			Method: "GET", Pattern: "/api/board/threads/{tid}",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzAuthenticated,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.boardGetThread),
		},
		{
			// Opens a new thread. Origin-guarded (the same posture every
			// participant board write below shares — reached ONLY from the
			// portal's browser fetch, never the collector's forward allowlist,
			// same reasoning ADR-0006 gave for declining to add P25's QA
			// there). audience defaults/coerces to 'admin' (private,
			// fail-closed) on anything but a literal 'admin'/'all' — see
			// boardCreateThread's own doc.
			Method: "POST", Pattern: "/api/board/threads",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzAuthenticated,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/10s burst 3 (shared with boardAppendMessage)",
			Handler:   h.og(boardPostMW(http.HandlerFunc(h.boardCreateThread))),
		},
		{
			// Follow-up on the caller's OWN thread only — board.Store.
			// AppendOwnMessage performs the ownership check and the insert
			// inside ONE call (no separate check-then-write pair); another
			// participant's {tid} 404s exactly like an unknown one.
			Method: "POST", Pattern: "/api/board/threads/{tid}/messages",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzAuthenticated,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/10s burst 3 (shared with boardCreateThread)",
			Handler:   h.og(boardPostMW(http.HandlerFunc(h.boardAppendMessage))),
		},
		{
			// Toggle a like on an audience='all' thread that is not the
			// caller's own — board.Store.Like enforces audience/state/
			// self-like fail-closed (ErrNotFound/ErrSelfLike) before the
			// insert. Own rate bucket, separate from the post bucket, so a
			// burst of likes can never starve a participant's ability to
			// open a thread or reply (and vice versa).
			Method: "POST", Pattern: "/api/board/threads/{tid}/like",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzAuthenticated,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (shared with boardUnlikeThread)",
			Handler:   h.og(boardLikeMW(http.HandlerFunc(h.boardLike))),
		},
		{
			// The like toggle's off state. board.Store.Unlike is an
			// unconditional, idempotent delete (there is nothing to leak by
			// allowing it unconditionally, unlike Like's insert path — see
			// that method's own doc).
			Method: "POST", Pattern: "/api/board/threads/{tid}/unlike",
			Audience: apispec.AudienceParticipant, Authz: apispec.AuthzAuthenticated,
			OriginGuarded: true, CollectorForward: false,
			RateLimit: "identity 1 req/s burst 10 (shared with boardLikeThread)",
			Handler:   h.og(boardLikeMW(http.HandlerFunc(h.boardUnlike))),
		},
		{
			// Operator moderation queue: every thread, every audience, every
			// state (hidden/deleted included) — board.Store.ListThreads(
			// isAdmin=true). No {user} in this route, same as P25's old
			// adminListQuestions before it.
			Method: "GET", Pattern: "/api/admin/board/threads",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.boardAdminListThreads),
		},
		{
			// Gap closed post-Phase-2-review: the operator's single-thread
			// FULL-TEXT read. board.Store.GetThread(viewer, isAdmin=true,
			// tid) bypasses the audience/ownership entitlement check
			// entirely (isAdmin=true) — hidden AND deleted threads are both
			// visible here, exactly like the moderation queue listing
			// above. A deleted MESSAGE's body is still scrubbed to "" by
			// the Store itself (board.go's own doc — deleting is a content
			// removal, not a from-participants-only hide, and that holds
			// for every viewer including admin). Returns the SAME
			// BoardThread shape the participant route does (toOapiBoardThread
			// is reused verbatim, #164 discipline) — one shape for "here is
			// the thread", regardless of which audience's route asked for
			// it.
			Method: "GET", Pattern: "/api/admin/board/threads/{tid}",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: false, CollectorForward: false, RateLimit: "none",
			Handler: http.HandlerFunc(h.boardAdminGetThread),
		},
		{
			// THE operator reply path — author is ALWAYS the fixed "staff"
			// constant (never the caller's raw email; see boardAdminReply's
			// own doc), author_role is ALWAYS admin. Origin-guarded like the
			// operator dashboard's other admin writes; never rate-limited,
			// matching that same trusted-actor precedent (P25's adminReply
			// before it).
			Method: "POST", Pattern: "/api/admin/board/threads/{tid}/reply",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.boardAdminReply)),
		},
		{
			// Thread moderation: pinned / answered / state, any combination.
			// MUST stay under /api/admin/ (never /api/board/) — the reverse
			// I15 ingress check treats every /api/admin/board/* route as
			// non-participant and the admin ingress's own /check-admin gate
			// is the second line of defense a /api/board/ placement would
			// lose.
			Method: "POST", Pattern: "/api/admin/board/threads/{tid}/state",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.boardAdminSetThreadState)),
		},
		{
			// Single-message moderation (e.g. hiding one abusive message
			// without touching the rest of the thread).
			Method: "POST", Pattern: "/api/admin/board/messages/{mid}/state",
			Audience: apispec.AudienceOperator, Authz: apispec.AuthzAdmin,
			OriginGuarded: true, CollectorForward: false, RateLimit: "none",
			Handler: h.og(http.HandlerFunc(h.boardAdminSetMessageState)),
		},
	}
}

// requireAuthenticated is the app#292 Phase 2 authz=authenticated gate
// primitive: any caller carrying a proven X-Auth-Request-Email identity may
// proceed. Unlike selfOrAdmin, it performs NO username-match against
// a {user} path segment — board routes carry no {user} segment at all
// (threads are addressed by their own {tid}, and ownership/audience/
// moderation-state entitlement checks live inside internal/board.Store
// itself, under the same lock hold as the read/write they gate — see that
// package's doc). A missing/blank header is fail-closed 403, the same
// "no proven identity -> deny" posture selfOrAdmin uses. Returns the
// lower/trimmed caller email and whether the request may proceed;
// board handlers derive the STORE identity to use (author/viewer) from
// UsernameFromEmail separately (see each handler's own doc) — this gate only
// answers "is anyone authenticated at all".
func (h *Handler) requireAuthenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		h.denials.Record(r, identityobs.GateAuthenticated, identityobs.ReasonNoIdentity)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return "", false
	}
	return email, true
}

// boardIdentity resolves a board participant route's caller identity in one
// call: requireAuthenticated first (the authz=authenticated gate this whole
// route family declares — any proven identity may proceed), then
// UsernameFromEmail to derive the SPECIFIC username value every board.Store
// call keys off (author/viewer). A header present but not shaped like a
// valid username slug (UsernameFromEmail returns "") is ALSO 403 — fail-closed,
// matching selfOrAdmin's own "no proven usable identity -> deny" posture;
// this NEVER falls back to the raw email as a Store author value (board
// authors are usernames, the same shape every other participant route in
// this package uses, not email addresses).
func (h *Handler) boardIdentity(w http.ResponseWriter, r *http.Request) (string, bool) {
	email, ok := h.requireAuthenticated(w, r)
	if !ok {
		return "", false
	}
	user := UsernameFromEmail(email, h.emailDomain)
	if user == "" {
		h.denials.Record(r, identityobs.GateAuthenticated, identityobs.ReasonNonCanonical)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return "", false
	}
	return user, true
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

// emailMatchesUser reports whether the auth-derived caller email is the given
// username's own identity: EXACT equality with the canonical `<user>@<domain>`
// (ADR-0034 D5, conventions I8). After auth-policy rewrites the identity
// headers to the canonical form, that is the only email a participant request
// carries; there is no prefix rule, so `user10@…` does not satisfy user1 and an
// email on any other domain (`user1@evil.example`) satisfies nobody. An empty
// domain makes every comparison false (fail-closed): a deployment that did not
// configure EXPECTED_EMAIL_DOMAIN locks participants out rather than letting any
// `alice@…` through.
//
// This is a mirror of auth-policy's canonical form, not a shared import beyond
// internal/identity's constants: auth-policy is a separate binary. The callers
// (selfOrAdmin) lower-case the header before calling in; the
// domain is lower-cased at construction.
func emailMatchesUser(email, user, domain string) bool {
	if email == "" || user == "" || domain == "" {
		return false
	}
	return email == identity.Canonical(user, domain)
}

// selfOrAdmin is the participant-facing read gate (P18). It derives the caller
// identity from X-Auth-Request-Email — the header oauth2-proxy injects on the
// single-origin portal host (P19-2b: `app.<dnsSuffix>/portal`, journey being
// one of the portal's tabs rather than its own host) and that auth-policy
// also propagates on the admin host — and authorizes the request for {user}
// iff:
//
//   - the caller email equals the canonical "<user>@<EXPECTED_EMAIL_DOMAIN>" exactly
//     (self, I8 — auth-policy rewrites the header to that form), OR
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
// the scoreboard need not know the hostname. The header is a PROOF of identity
// only while three things outside this file hold (it is not unforgeable by
// itself). These three conditions are the premise of I8 (canonical source: I8 in
// .claude/rules/falco-ctf-app-conventions.md; machine checks: V12 / V13;
// NetworkPolicy: charts/scoreboard/templates/networkpolicy.yaml):
// (1) the scoreboard ingresses keep their auth-url pointed at
// auth-policy (/check-participant, /check-admin) and keep the
// `auth-response-headers` annotation pinned, so ingress-nginx overwrites a
// client-supplied copy of exactly those listed headers (not every
// X-Auth-Request-*; the scoreboard trusts -Email only) with auth-policy's
// response. For a participant seat auth-policy stamps the canonical
// `<seat>@<domain>` form (stampCanonical), which is why one seat maps to one
// identity (and one rate-limit bucket); only an ADMIN_EMAILS identity is passed
// through verbatim as oauth2-proxy reported it, and the scoreboard lower-cases
// it on the reading side (see the ToLower below); (2) the scoreboard
// NetworkPolicy keeps participant-controlled workloads (workspaces) off the
// Service: it admits the falco and ingress-nginx namespaces and the namespace
// labelled for the collector, so the only senders that can reach it are
// platform components, and only with a CNI that enforces NetworkPolicy;
// (3) the collector forwards only its allowlisted routes (submit-detect is not
// one of them) and strips every inbound X-Auth-Request-* (ADR-0034 D6).
func (h *Handler) selfOrAdmin(w http.ResponseWriter, r *http.Request, user string) bool {
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Auth-Request-Email")))
	if email == "" {
		// fail-closed: no proven identity → deny (do not fall back to {user}).
		h.denials.Record(r, identityobs.GateSelfOrAdmin, identityobs.ReasonNoIdentity)
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return false
	}
	if _, ok := h.adminSet[email]; ok {
		return true
	}
	if emailMatchesUser(email, user, h.emailDomain) {
		return true
	}
	// The gate judges the reason, the observer only records it (ADR-0038 D2):
	// a header that is not a canonical <seat>@<domain> is a configuration fault
	// (non_canonical, also when EXPECTED_EMAIL_DOMAIN is empty); a canonical
	// identity for another seat is the participant's own doing (mismatch). The
	// caller's email and the {user} path value are not logged (D4).
	reason := identityobs.ReasonMismatch
	if UsernameFromEmail(email, h.emailDomain) == "" {
		reason = identityobs.ReasonNonCanonical
	}
	h.denials.Record(r, identityobs.GateSelfOrAdmin, reason)
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
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgResetFailed})
		return
	}
	h.logger.Info("scoreboard reset", "by", email, "cleared_solves", n)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared_solves": n})
}

// zeroWidthJoiner (U+200D) is the one Cf character displayNameHasForbidden
// lets through, and only between two emoji (see isEmojiBase / isEmojiPrefix).
const zeroWidthJoiner = '\u200d'

// isEmojiPrefix reports whether r may immediately precede a ZWJ in an emoji
// sequence: an emoji base (Symbol, other: U+1F469, U+2764, ...), a skin-tone
// modifier (U+1F3FB-1F3FF) or the emoji variation selector
// U+FE0F (which follows bases such as U+2764 and U+1F3F3). Letters, digits and
// punctuation are NOT emoji, so "Alice" + ZWJ stays rejected.
func isEmojiPrefix(r rune) bool {
	return r == '\ufe0f' || (r >= 0x1f3fb && r <= 0x1f3ff) || unicode.Is(unicode.So, r)
}

// isEmojiBase reports whether r may immediately follow a ZWJ: an emoji base.
func isEmojiBase(r rune) bool { return unicode.Is(unicode.So, r) }

// displayNameHasForbidden reports whether name contains a rune
// invalidDisplayName matches, other than a U+200D that sits directly between
// an emoji prefix and an emoji base. A ZWJ at either end, two ZWJs in a row,
// or a ZWJ next to a letter (any non-emoji) is forbidden like every other Cf.
// NFC normalisation is deliberately NOT done here: see the app#331 note on
// validDisplayName.
//
// Subdivision flags (England / Scotland / Wales: U+1F3F4 + tag characters
// U+E0020-E007F, which are Cf) are therefore refused too. That is accepted on
// purpose (review-5x 16, app#381): a tag run is an invisible-text carrier, and
// the table pins it (cases.yaml, "England flag").
func displayNameHasForbidden(name string) bool {
	return hasForbiddenRune(name, invalidDisplayName)
}

// inlineTextHasForbidden is displayNameHasForbidden for inline prose (a board
// subject, app#377): the same Cc / Cf refusal and the same ZWJ-between-emoji
// exception (one scan, hasForbiddenRune), without the metacharacters. Both are
// swept against testdata/display-name-parity/rule.yaml.
func inlineTextHasForbidden(s string) bool {
	return hasForbiddenRune(s, invalidInlineText)
}

// hasForbiddenRune is the one scan behind both predicates: class says what is
// refused, and a ZWJ is the one exception (see displayNameHasForbidden).
func hasForbiddenRune(s string, class *regexp.Regexp) bool {
	runes := []rune(s)
	for i, r := range runes {
		if r == zeroWidthJoiner {
			if i > 0 && i+1 < len(runes) && isEmojiPrefix(runes[i-1]) && isEmojiBase(runes[i+1]) {
				continue
			}
			return true
		}
		if class.MatchString(string(r)) {
			return true
		}
	}
	return false
}

// errDisplayNameFlagShape is validDisplayName's refusal of a flag shape, a sentinel so
// a caller can tell it from the other refusals and log it (logFlagShapeRefused).
var errDisplayNameFlagShape = errors.New(errMsgDisplayNameFlagShape)

// validDisplayName trims + validates a display name: 1..32 runes, no HTML/shell
// metachars, no control (C0/C1) or format (Cf) characters (app#331; a ZWJ
// between emoji is the one allowed Cf), and no flag shape (flagShapePattern,
// app#402). Shared by the participant profile
// route (profile.go) and the admin set-display-name endpoint, so both reject
// the same names.
//
// Whitespace is trimmed first (strings.TrimSpace), so a name that is only
// padded at the ends by U+0085 NEL / NBSP / tabs is stored as the trimmed
// name; the same characters in the MIDDLE are rejected (Cc) or kept (NBSP is
// Zs, not Cc/Cf — see the app#331 residuals).
//
// NFC (app#331 question): not applied. Normalising only collapses canonically
// equivalent spellings of one string ("é" as U+00E9 vs "e"+U+0301) to the same
// bytes; it would matter if display names had to be UNIQUE (they do not:
// duplicates are allowed), and it would not stop invisible characters
// (they are not a normalisation difference). It would add
// golang.org/x/text/unicode/norm as a direct dependency for no security
// gain, so revisit it together with a uniqueness rule, not before.
func validDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("name required")
	}
	if utf8.RuneCountInString(name) > 32 {
		return "", fmt.Errorf("name too long (max 32 runes)")
	}
	if displayNameHasForbidden(name) {
		return "", fmt.Errorf("name contains forbidden characters")
	}
	// app#402: flagShapePattern (app#292) gates every other free text a participant
	// shows to the others (a board subject and body); a name is shown to the others too
	// (the author of an audience=all board thread, read from the store at display time,
	// and the operator's projected dashboard), so it is gated by the same SHAPE. It is
	// a pattern rule, not a character class: it is pinned by cases.yaml and
	// display_name_flag_shape_test.go, not by the code-point sweep (rule.yaml), and
	// the form leaves it to the server (a form is never stricter than the server).
	if flagShapePattern.MatchString(name) {
		return "", errDisplayNameFlagShape
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
	if !identity.ValidSeat(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("admin set display name: invalid body", "err", err, "remote_addr", r.RemoteAddr)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	name, err := validDisplayName(req.Name)
	if err != nil {
		if errors.Is(err, errDisplayNameFlagShape) {
			h.logFlagShapeRefused(r, user, flagFieldDisplayName)
		}
		// Self-crafted validation message (validDisplayName), not an
		// internal/store error — safe to return verbatim.
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	at := h.now().UTC().Format(time.RFC3339Nano)
	if err := h.store.SetDisplayName(user, name, at); err != nil {
		h.logger.Error("admin set display name", "err", err, "user", user)
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": errMsgSetDisplayNameFailed})
		return
	}
	h.logger.Info("admin display_name", "user", user, "display_name", name, "remote_addr", r.RemoteAddr)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user, "display_name": name})
}

// --- submit -----------------------------------------------------------------

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	ch, label, found := h.challenge(cid)
	// auditLog: every branch below records a structured line so post-event
	// triage can answer "who submitted what flag against which challenge",
	// even when the result is rejection. Identity (`user`) is claimed by
	// the request body — never verified — so always log the source address
	// alongside it for cross-referencing.
	auditLog := func(outcome string, extra ...any) {
		fields := []any{
			"cid", label,
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
	if !found {
		metrics.SubmissionsTotal.WithLabelValues(label, "unknown_challenge").Inc()
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
		return
	}
	if ch.Type != "evade" {
		metrics.SubmissionsTotal.WithLabelValues(label, "not_evade").Inc()
		auditLog("not_evade")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": cid + " is not an evade challenge"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	var req oapi.SubmitFlagJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "err", err.Error())
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	user := strings.TrimSpace(req.User)
	flag := strings.TrimSpace(req.Flag)

	if user == "" {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "reason", "missing user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user required"})
		return
	}
	// The body's user is claimed (the collector forwards it verbatim), but it
	// is STORED and later shown as first_solver, so it must at least be a slug
	// (identity.ValidSeat). Fixed text, the input is not echoed (#428).
	if !identity.ValidSeat(user) {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "reason", "invalid user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}

	// Solve decision (flag match → evade window → exfil gate → record) is the
	// Grader's. This handler only translates the outcome into a response +
	// metric + audit line. The window is evaluated against server time inside
	// the Grader (App-H3) — the handler never passes attacker-supplied time.
	outcome, err := h.gradeEvade(user, cid, flag)
	if errors.Is(err, scoring.ErrInvalidUser) {
		h.refuseGraderUser(w, r, scoring.EntrySubmitEvade, func() {
			metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
			auditLog("bad_request")
		})
		return
	}
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
		metrics.SubmissionsTotal.WithLabelValues(label, "wrong_flag").Inc()
		auditLog("wrong_flag", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"correct": false, "reason": "flag mismatch"})
	case scoring.EvadeForbiddenFired:
		metrics.SubmissionsTotal.WithLabelValues(label, "not_evaded").Inc()
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
		metrics.SubmissionsTotal.WithLabelValues(label, "not_proven").Inc()
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
		metrics.SubmissionsTotal.WithLabelValues(label, "not_exfiltrated").Inc()
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
			metrics.SolvesTotal.WithLabelValues(label, "evade").Inc()
		}
		metrics.SubmissionsTotal.WithLabelValues(label, "solved").Inc()
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
// challenge. It is browser-only (origin-guarded, not in the collector's
// forward allowlist) and, since app#328, is gated by detectMW (identity-keyed
// rate limit, 403 without the X-Auth-Request-Email header) then selfOrAdmin
// (header REQUIRED). It adds two detect-specific controls:
//
//   - self-scope: the identity header is REQUIRED (selfOrAdmin; app#346). The
//     claimed body user must equal the proven identity's canonical form
//     (ADR-0034 S2: exact match); an admin may grade for any user. A request
//     with no X-Auth-Request-Email — the cluster-internal Service path, which
//     has no legitimate caller for this route (the collector does not forward
//     it and NetworkPolicy keeps workspaces off it) — is 403.
//     The header is trusted only while the conditions on selfOrAdmin hold (the
//     ingress auth-response-headers pin, the scoreboard NetworkPolicy, and the
//     collector NOT forwarding this route while stripping X-Auth-Request-*):
//     do not add submit-detect to the collector's forward allowlist.
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
	ch, label, found := h.challenge(cid)
	auditLog := func(outcome string, extra ...any) {
		fields := []any{"cid", label, "remote_addr", r.RemoteAddr, "outcome", outcome}
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
	if !found {
		metrics.SubmissionsTotal.WithLabelValues(label, "unknown_challenge").Inc()
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
		return
	}
	if ch.Type != "detect" {
		metrics.SubmissionsTotal.WithLabelValues(label, "not_detect").Inc()
		auditLog("not_detect")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": cid + " is not a detect challenge"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, detect.MaxConditionBytes+1<<10)
	var req oapi.SubmitDetectJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "err", err.Error())
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	user := strings.TrimSpace(req.User)
	condition := strings.TrimSpace(req.Condition)
	if user == "" {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "reason", "missing user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user required"})
		return
	}
	if !identity.ValidSeat(user) {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "reason", "invalid user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	// Self-scope: the identity header is REQUIRED (header-less is 403) and the
	// body user must equal the proven identity's canonical form (or the caller
	// be an admin). Uses validated `user` for the exact canonical-form match.
	if !h.selfOrAdmin(w, r, user) {
		auditLog("forbidden", "user", user)
		return
	}
	if condition == "" {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
		auditLog("bad_request", "user", user, "reason", "missing condition")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "condition required"})
		return
	}
	if len(condition) > detect.MaxConditionBytes {
		metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
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
		metrics.SubmissionsTotal.WithLabelValues(label, "rate_limited").Inc()
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
	outcome, err := h.gradeDetect(ctx, h.detectRunner, user, cid, condition)
	if errors.Is(err, scoring.ErrInvalidUser) {
		h.refuseGraderUser(w, r, scoring.EntrySubmitDetect, func() {
			metrics.SubmissionsTotal.WithLabelValues(label, "bad_request").Inc()
			auditLog("bad_request")
		})
		return
	}
	if err != nil {
		// Fail closed: a runner infra error is a 500, never a silent solve.
		h.logger.Error("grade detect", "err", err, "cid", cid, "user", user)
		auditLog("error", "user", user, "err", err.Error())
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not grade condition"})
		return
	}
	switch outcome.Status {
	case scoring.DetectInvalidCondition:
		metrics.SubmissionsTotal.WithLabelValues(label, "detect_invalid").Inc()
		auditLog("invalid", "user", user)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "invalid",
			"solved": false,
			"reason": "the condition did not compile (falco -V rejected it). Check the syntax and the macros you referenced.",
		})
	case scoring.DetectMissedEvasion:
		metrics.SubmissionsTotal.WithLabelValues(label, "detect_missed").Inc()
		auditLog("missed", "user", user, "evasion_fires", outcome.EvasionFires, "benign_fires", outcome.BenignFires)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        "missed",
			"solved":        false,
			"evasion_fires": outcome.EvasionFires,
			"benign_fires":  outcome.BenignFires,
			"reason":        "your rule did not fire on the attack capture. It fired 0× on the evasion — it is not detecting the behaviour.",
		})
	case scoring.DetectFalsePositive:
		metrics.SubmissionsTotal.WithLabelValues(label, "detect_false_positive").Inc()
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
			metrics.SolvesTotal.WithLabelValues(label, "detect").Inc()
		}
		metrics.SubmissionsTotal.WithLabelValues(label, "solved").Inc()
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
// ctf-user). The browser path is refused outright: any X-Auth-Request-* header
// => 403, a non-JSON Content-Type => 415 (see the checks at the top). The flag is matched at submit time (RequireExfil via HasExfil), so
// a wrong value recorded here simply fails the eventual submit.
func (h *Handler) exfilInternal(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	ch, label, found := h.challenge(cid)
	auditLog := func(outcome string, extra ...any) {
		fields := []any{"cid", label, "remote_addr", r.RemoteAddr, "outcome", outcome}
		fields = append(fields, extra...)
		h.logger.Info("exfil_internal", fields...)
	}

	// Collector-only: the browser path (admin ingress catch-all ->
	// oauth2-proxy) always carries X-Auth-Request-*, the collector never does.
	// Refused before ANY other check so nothing (not even 404 / 400) varies with
	// the request's content, and a cross-origin POST from an admin session
	// (same-site under SameSite=Lax, any site if the cookie went back to None;
	// this refusal does not depend on the attribute, ADR-0049 D3) can neither
	// record a receipt nor probe the catalog.
	if httpx.HasProxyIdentityHeader(r) {
		auditLog("browser_path_denied")
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	if !httpx.IsJSONContentType(r) {
		auditLog("unsupported_media_type")
		httpx.WriteJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": errMsgUnsupportedMediaType})
		return
	}

	// Pre-body guards (unknown challenge / exfil not accepted) gate whether we
	// read the body at all, matching the prior order. Their verdict is the
	// Grader's — RecordExfil re-applies the same guards before recording.
	if !found {
		auditLog("unknown_challenge")
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
		return
	}
	if !ch.RequireExfil {
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
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
		return
	}
	user := strings.TrimSpace(req.User)
	flag := strings.TrimSpace(req.Flag)
	if user == "" || flag == "" {
		auditLog("bad_request", "reason", "missing user or flag")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "user and flag required"})
		return
	}
	// Same slug rule as /submit: this user is stored in the receipt and is what
	// the grader later joins to a solve (#428). Fixed text, input not echoed.
	if !identity.ValidSeat(user) {
		auditLog("bad_request", "reason", "invalid user")
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}

	// Recording the collector receipt (with its catalog/RequireExfil guards and
	// receipt timestamp) is the Grader's job; the guards above have already
	// short-circuited the unknown / not-required cases, so here the Grader
	// returns ExfilRecorded (or a store error).
	if _, err := h.recordExfil(user, cid, flag); errors.Is(err, scoring.ErrInvalidUser) {
		h.refuseGraderUser(w, r, scoring.EntryRecordExfil, func() { auditLog("bad_request") })
		return
	} else if err != nil {
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

// refuseGraderUser answers a Grader entry that refused the body's user with
// scoring.ErrInvalidUser: the Grader's SECOND seat gate (app#479). The handler's
// own identity.ValidSeat answered first, so reaching this means the handler lost
// that check; the answer is still the first gate's, 400 {"error": "invalid user"}
// (never a 500, the refused value is not echoed), plus the one fixed-field Warn.
// record is the caller's metric / audit line for the refusal, run before the
// answer. The three Grader entries a body user reaches (SubmitEvade, SubmitDetect,
// RecordExfil) share this one block.
func (h *Handler) refuseGraderUser(w http.ResponseWriter, r *http.Request, entry string, record func()) {
	identityobs.LogGraderRefused(h.logger, r, entry)
	record()
	httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
}

// --- Journey step self-check ------------------------------------------------

// stepCheck ticks (checked=true) or clears (checked=false) step {idx} (0-based)
// of {cid} for {user}. Purely presentational: journey `steps` are an info-only
// checklist with no auto-detection, so a tick never affects the solve verdict —
// it just lets a participant track their own progress across page reloads.
// Auth: actionMW (identity rate limit, 403 without the header) then
// selfOrAdmin (header REQUIRED, self-or-admin). Unlike /submit there is no
// claimed-identity branch: this route is browser-only (origin-guarded).
//
// Body:  {"checked": true}
// Route: POST /api/users/{user}/challenges/{cid}/steps/{idx}/check
func (h *Handler) stepCheck(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	cid := r.PathValue("cid")
	if !identity.ValidSeat(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}
	if _, _, ok := h.challenge(cid); !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
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
		h.logger.Warn("step check: invalid body", "err", err, "user", user, "cid", cid, "idx", idx)
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": errMsgInvalidBody})
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
	if !identity.ValidSeat(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}
	if _, _, ok := h.challenge(cid); !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
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
	hint := j.Hints[idx-1]
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"user":  user,
		"cid":   cid,
		"idx":   idx,
		"hint":  hint.Text,
		"total": len(j.Hints),
		"newly": newly,
		// kind/ruleRefs/cheatsheetRef (unified hints Phase 1): additive fields
		// the portal uses to render the Hint1=Rule+link / Hint2=Command+link /
		// Hint3=想定解 treatment. RuleRefs/CheatsheetRef are normalised to
		// non-nil so they always marshal as JSON [] / "" (never null/omitted).
		"kind":          hint.Kind,
		"ruleRefs":      nonNilStrings(hint.RuleRefs),
		"cheatsheetRef": hint.CheatsheetRef,
	})
}

// nonNilStrings normalises a possibly-nil []string to a non-nil empty slice
// so JSON marshals it as `[]` rather than `null`. journey.yaml hints commonly
// omit ruleRefs entirely (back-compat scalar form always does).
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
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
// Auth: selfOrAdmin (same as stepCheck / openHint; the identity header is
// REQUIRED) — over the auth-proxied journey/admin host a participant may only
// reset their OWN {user}'s taint; an admin may reset any. A header-less caller
// is 403'd twice over: by actionMW (MiddlewareStrict, no identity -> 403) and
// by selfOrAdmin itself; h.og (originguard.Guard) also 403s any request
// carrying neither an Origin nor a Referer before either runs. All three
// layers are deliberate (app#124 5x review, R1 finding C3): A2-2 made this
// endpoint able to delete ANOTHER participant's collector exfil receipt, and
// the claimed-identity model carries no proof the caller IS that participant.
// Do not remove h.og from this route's registration, do not swap the gate
// back to a gate that lets a header-less caller through, and do not add this path to the collector's
// forwarding allowlist (internal/collector/collector.go) — any of those would
// reopen exactly that path.
func (h *Handler) resetDirty(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	cid := r.PathValue("cid")
	if !identity.ValidSeat(user) {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user"})
		return
	}
	if !h.selfOrAdmin(w, r, user) {
		return
	}
	ch, _, ok := h.challenge(cid)
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{"error": errMsgUnknownChallenge})
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

// --- request-shape helpers shared by collector-only / JSON-only writes -------

// errMsgUnsupportedMediaType is the stable 415 body for routes that require a
// JSON request body.
const errMsgUnsupportedMediaType = "content type must be application/json"

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
	if !identity.ValidSeat(user) {
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
		"avatar":            avatar.Resolve(snap.Avatars[user], user),
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
// advantage. Progressive hints and step ticks are NOT gated by status either
// (ADR-0027, CEO decision 2026-10-04: a skipped mission's hints may be
// opened at the normal point cost): `detail.hints` and `detail.steps[].checked`
// are a function of the store alone — see missionDetail. `status` is a
// guidance label for the participant ("not reached yet"), not an access
// control; the write side (openHint / stepCheck) never consulted it.
// An invalid/unknown `?mission=` value is ignored (falls back to `current`)
// rather than erroring — this is a display convenience, not an API contract
// participants depend on for scoring.
func (h *Handler) journey(w http.ResponseWriter, r *http.Request) {
	user := strings.TrimSpace(r.PathValue("user"))
	if !identity.ValidSeat(user) {
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
	// selection's own status (reported as detail.status) without re-deriving
	// the solved/current/locked rule a second time inline.
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
			// Guided progression: everything after the current mission is
			// "locked" — a guidance label only (ADR-0027 D2); it restricts no read.
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
		"avatar":       avatar.Resolve(snap.Avatars[user], user),
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
// status is the mission's projected status (solved | current | locked) and is
// reported verbatim as `status`. It is a guidance label only (ADR-0027 D2):
// nothing in this function branches on it. In particular `hints`
// (opened / lockedCount / nextIndex / penalty) and `steps[].checked` are a
// function of checkedSteps / openedHints (the store) ALONE, so a skipped
// ("locked") mission shows exactly the hints the participant opened and the
// ticks they made — the write side (openHint / stepCheck) never consulted
// status, and a projection that did made a billed hint invisible. Before
// ADR-0027 (CEO decision 2026-08-17) a locked mission's hints were hidden
// here and its steps were forced unchecked; CEO decision 2026-10-04 reversed
// that. `hints.lockedCount` keeps its name and means "not opened yet".
func (h *Handler) missionDetail(user, cid, status, leadIn string, checkedSteps, openedHints []int) map[string]any {
	ch := h.cat[cid]
	j, hasJourney := h.journeys[cid]

	// Step ticks are the participant's own data and have no scoring effect (a
	// tick never affects the solve verdict); they are projected as stored,
	// whatever the mission's status.
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

	// Hints are projected from the store's opened set, whatever the mission's
	// status (see the doc above).
	opened := make(map[int]struct{}, len(openedHints))
	for _, i := range openedHints {
		opened[i] = struct{}{}
	}
	type hintView struct {
		Idx           int      `json:"idx"`
		Text          string   `json:"text"`
		Kind          string   `json:"kind"`
		RuleRefs      []string `json:"ruleRefs"`
		CheatsheetRef string   `json:"cheatsheetRef"`
	}
	openedList := make([]hintView, 0, len(opened))
	nextHint := 0 // 1-based index of the next unopened hint; 0 = all opened
	for i := 1; i <= len(j.Hints); i++ {
		if _, ok := opened[i]; ok {
			h := j.Hints[i-1]
			openedList = append(openedList, hintView{
				Idx: i, Text: h.Text, Kind: h.Kind,
				RuleRefs: nonNilStrings(h.RuleRefs), CheatsheetRef: h.CheatsheetRef,
			})
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
	// (solved/current/locked; see this function's doc). A
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
	// (solved/current/locked): these are Falco rule NAMES only,
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
			// nextHint is 0 — all opened) costs
			// nothing, matching "there is nothing left to reveal". Projection
			// only — the score arithmetic stays in the scoring layer.
			// NoHintPenalty challenges (00-tutorial) always project 0 here —
			// must agree with scoring.Grader.UserScore's own exemption, or the
			// "open hint" button would advertise a cost that never actually
			// gets deducted.
			"penalty": func() int {
				if ch.NoHintPenalty {
					return 0
				}
				return h.grader.HintPenaltyFor(nextHint)
			}(),
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
	// Avatar is the always-present avatar id (ADR-0034 D8): the stored id, or
	// the seat's default when none is stored / the stored id left the table.
	// Display-only — it never feeds Score or Rank.
	Avatar string `json:"avatar"`
	Solved int    `json:"solved"`
	// Score is the ranking metric (#40, CEO decision): the Grader's points
	// arithmetic (base award per solve − per-hint reveal penalty, clamped at
	// 0). Additive alongside Solved/Earliest so per-challenge progress bars
	// still read solved counts; ranking keys off Score with Earliest as the
	// tiebreak. Derived via grader.UserScore (ComputeScore single source) — no
	// inline points math here (#39 direction).
	//
	// 2026-09-03 CEO decision (live 2026-09-03 event): Earliest now holds the
	// user's MOST RECENT solve timestamp, not their first. Challenges are
	// solved in a fixed order ending at the final mission, so "most recent
	// solve" is the completion-order signal for players tied at the same
	// score — whoever reached that score soonest ranks first. The prior
	// "first-blood" tiebreak (earliest FIRST solve, e.g. the tutorial) let a
	// player who started fast but finished slow outrank someone who actually
	// finished earlier, which is not the intended notion of "official"
	// ranking. JSON field name kept as "earliest" (no frontend renders it
	// directly — verified 2026-09-03 — so the rename is deploy-safe without a
	// wider contract change).
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
//
// HIDDEN_USERS (CEO/ops request): any user in h.hiddenSet is excluded from
// the userSet this function builds below, so they never get an lbEntry —
// they contribute no row to buildState's venue-projection leaderboard and
// rank consecutively for everyone else (no gap left where the hidden user
// would have sorted). This is a DISPLAY filter only: it does not touch
// scoring (the hidden user's own solves/score are computed and stored
// exactly as normal), and it does not affect userMe's OWN row for that
// user — userMe pre-computes its own score independently of this
// function's output and only overwrites it by finding a matching lbEntry
// here, so a hidden user reading their own /me still sees their real score
// (with rank falling back to userMe's zero-value default, same as any
// zero-solve participant).
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
		if _, hidden := h.hiddenSet[u]; hidden {
			continue
		}
		userSet[u] = struct{}{}
	}
	for k := range snap.Solved {
		if _, ok := idSet[k.Challenge]; !ok {
			continue
		}
		if _, hidden := h.hiddenSet[k.User]; hidden {
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
		// Track the MOST RECENT solve (not the first) — see lbEntry.Score doc
		// comment above (2026-09-03 CEO decision). "" sorts before every real
		// RFC3339 timestamp, so any real solve overwrites it; the "9999"
		// sentinel is applied after the loop for zero-solve users so it still
		// sorts last in the ascending tiebreak comparison below.
		latest := ""
		for _, p := range perUserSolves[u] {
			if p[1] > latest {
				latest = p[1]
			}
		}
		if latest == "" {
			latest = "9999"
		}
		solved := len(perUserSolves[u])
		leaderboard = append(leaderboard, lbEntry{
			User:        u,
			DisplayName: displayOf(u),
			Avatar:      avatar.Resolve(snap.Avatars[u], u),
			Solved:      solved,
			// Score is the Grader's arithmetic; the handler only projects it. Pass
			// the same catalog-filtered solved count used for the Solved column so
			// the two agree, and the Grader adds the per-hint reveal penalty.
			Score:    h.grader.UserScore(u, solved),
			Earliest: latest,
			Events:   snap.EventsPerUser[u],
		})
	}
	// Rank by Score desc (#40, CEO decision — the leaderboard order now reflects
	// the hint-penalty score, so a player who solved the same set with fewer
	// hints outranks one who leaned on hints), with Earliest (now: most recent
	// solve) as the tiebreak — this is a completion-order tiebreak, not
	// first-blood (2026-09-03 CEO decision, see lbEntry.Score doc above).
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
	avatarOf := func(u string) string { return avatar.Resolve(snap.Avatars[u], u) }

	type chSolver struct {
		User        string `json:"user"`
		DisplayName string `json:"display_name"`
		Avatar      string `json:"avatar"`
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
			details = append(details, chSolver{User: s[0], DisplayName: displayOf(s[0]), Avatar: avatarOf(s[0]), At: s[1]})
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
		Avatar      string `json:"avatar"`
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
			Avatar:      avatarOf(k.User),
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
