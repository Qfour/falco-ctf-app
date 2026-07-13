// Package scoring holds the scoreboard's solve-decision business rules as a
// single domain service (Grader). It is the one place that decides whether a
// participant has solved a challenge and the sole caller of the store's
// MarkSolved — reinforcing the single-writer discipline (conventions I1).
//
// Before this package the verdict logic was spread across three handler sites:
//
//   - ingest (trigger auto-solve on a Falco rule fire),
//   - api /submit (evade flag + forbidden-window + exfil gate),
//   - api /internal/exfil (recording the collector receipt that the gate reads).
//
// The Grader collects those into EvaluateTrigger / SubmitEvade / RecordExfil so
// the rules can be unit-tested without HTTP, and so the ingest / api handlers
// become thin inbound adapters (drivers) that only translate the returned
// outcome into a response + metrics.
//
// Dependency direction: scoring depends on catalog (challenge metadata) and on
// the ScoreStore port; it never imports the handlers. The concrete *store.Store
// satisfies ScoreStore, so the store is a repository adapter behind the port.
package scoring

import (
	"errors"
	"slices"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// ScoreStore is the repository port the Grader depends on. It is the minimal
// slice of the persistence layer the solve rules need; *store.Store implements
// it. Keeping the Grader behind this interface makes the rules unit-testable
// with a fake store + fake clock (see scoring_test.go).
//
// The methods mirror the existing store signatures verbatim so the refactor is
// behaviour-preserving:
//   - MarkSolved is idempotent (first solve wins) and reports whether the solve
//     was newly recorded.
//   - RecentForbiddenFires returns the set of forbidden rules that fired for the
//     user within windowSeconds of now (unix seconds); empty = clean window.
//   - HasExfil reports whether the user delivered exactly this flag to the
//     collector for this challenge.
type ScoreStore interface {
	MarkSolved(user, challenge, at string) (newly bool, err error)
	RecentForbiddenFires(user string, forbidden []string, now float64, windowSeconds int) []string
	HasExfil(user, challenge, flag string) bool
	RecordExfil(user, challenge, flag, at string) error
}

// Grader is the scoring domain service. It owns the catalog (challenge rules)
// and the clock, and is the only component that calls MarkSolved.
type Grader struct {
	cat   catalog.Catalog
	store ScoreStore
	now   func() time.Time
}

// New builds a Grader. `now` is injected (WithNow pattern) so tests drive a
// deterministic clock; production wires time.Now.
func New(cat catalog.Catalog, store ScoreStore, now func() time.Time) *Grader {
	if now == nil {
		now = time.Now
	}
	return &Grader{cat: cat, store: store, now: now}
}

// TriggerResult reports, per challenge, whether a Falco rule fire solved it.
// Newly is true only the first time that (user, challenge) is recorded, so the
// adapter can decide when to bump the solve metric (behaviour-identical to the
// old inline loop).
type TriggerResult struct {
	Challenge string
	Newly     bool
}

// EvaluateTrigger applies a single Falco rule fire to every trigger-type
// challenge whose expectedRules contain `rule`, marking each solved. It mirrors
// the old ingest loop exactly: iterate catalog ids in order, skip non-trigger
// challenges and non-matching rules, MarkSolved for the rest.
//
// Store errors are continue-on-error, exactly as the old ingest loop was: a
// failing MarkSolved skips only that challenge (the others still get marked)
// and the failures are collected and returned joined via errors.Join. The
// adapter logs the joined error and still uses the successful results — so one
// challenge's transient DB error never suppresses solves for the others.
func (g *Grader) EvaluateTrigger(user, rule string) ([]TriggerResult, error) {
	var results []TriggerResult
	var errs []error
	recvAt := g.now().UTC().Format(time.RFC3339Nano)
	for _, cid := range g.cat.IDs() {
		ch := g.cat[cid]
		if ch.Type != "trigger" {
			continue
		}
		if !slices.Contains(ch.ExpectedRules, rule) {
			continue
		}
		newly, err := g.store.MarkSolved(user, cid, recvAt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, TriggerResult{Challenge: cid, Newly: newly})
	}
	return results, errors.Join(errs...)
}

// EvadeStatus enumerates the outcome of an evade-challenge submission. The
// handler maps each value to the same HTTP response shape it produced inline
// before the extraction.
type EvadeStatus int

const (
	// EvadeUnknownChallenge: cid is not in the catalog.
	EvadeUnknownChallenge EvadeStatus = iota
	// EvadeNotEvadeType: the challenge exists but is not an evade challenge.
	EvadeNotEvadeType
	// EvadeWrongFlag: the submitted flag does not match expectedFlag.
	EvadeWrongFlag
	// EvadeForbiddenFired: flag correct, but a forbidden rule fired inside the
	// window (offending rules populated).
	EvadeForbiddenFired
	// EvadeExfilRequired: flag correct + window clean, but the challenge
	// requires exfil and the collector has not received the matching flag.
	EvadeExfilRequired
	// EvadeSolved: all gates passed; the solve was recorded (Newly reports
	// whether it was the first time).
	EvadeSolved
)

// EvadeOutcome is the full result of SubmitEvade. Only the fields relevant to
// Status are populated:
//   - EvadeForbiddenFired: Offending holds the sorted forbidden rules.
//   - EvadeSolved: Newly reports whether this was the first solve.
type EvadeOutcome struct {
	Status    EvadeStatus
	Offending []string // forbidden rules that fired (EvadeForbiddenFired only)
	Newly     bool     // first-time solve (EvadeSolved only)
}

// SubmitEvade evaluates an evade-challenge flag submission through the same
// ordered gates the /submit handler used inline:
//
//  1. challenge exists (else EvadeUnknownChallenge)
//  2. challenge is evade type (else EvadeNotEvadeType)
//  3. flag matches expectedFlag (else EvadeWrongFlag)
//  4. no forbidden rule fired within windowSeconds of server now (else
//     EvadeForbiddenFired) — the window is evaluated against server time and
//     never references attacker-supplied time: now derives from g.now(), not
//     from any event field.
//  5. if RequireExfil, the collector has the matching flag (else
//     EvadeExfilRequired)
//  6. record the solve → EvadeSolved.
//
// `flag` is expected pre-trimmed by the adapter (the handler trims user input),
// matching the prior behaviour where the comparison and the exfil lookup both
// used the trimmed value.
func (g *Grader) SubmitEvade(user, cid, flag string) (EvadeOutcome, error) {
	ch, ok := g.cat[cid]
	if !ok {
		return EvadeOutcome{Status: EvadeUnknownChallenge}, nil
	}
	if ch.Type != "evade" {
		return EvadeOutcome{Status: EvadeNotEvadeType}, nil
	}
	if flag != ch.ExpectedFlag {
		return EvadeOutcome{Status: EvadeWrongFlag}, nil
	}

	// Forbidden-rule window: server now(), never attacker-supplied time.
	now := float64(g.now().Unix())
	offending := g.store.RecentForbiddenFires(user, ch.ForbiddenRules, now, ch.WindowSeconds)
	if len(offending) > 0 {
		return EvadeOutcome{Status: EvadeForbiddenFired, Offending: offending}, nil
	}
	if ch.RequireExfil && !g.store.HasExfil(user, cid, flag) {
		return EvadeOutcome{Status: EvadeExfilRequired}, nil
	}

	at := g.now().UTC().Format(time.RFC3339Nano)
	newly, err := g.store.MarkSolved(user, cid, at)
	if err != nil {
		return EvadeOutcome{}, err
	}
	return EvadeOutcome{Status: EvadeSolved, Newly: newly}, nil
}

// ExfilStatus enumerates the outcome of recording a collector exfil receipt.
type ExfilStatus int

const (
	// ExfilUnknownChallenge: cid is not in the catalog.
	ExfilUnknownChallenge ExfilStatus = iota
	// ExfilNotRequired: the challenge does not accept exfil (RequireExfil false).
	ExfilNotRequired
	// ExfilRecorded: the receipt was stored (last-write-wins per user/challenge).
	ExfilRecorded
)

// RecordExfil stores a collector exfil receipt for the boss capstone, applying
// the same guards the /internal/exfil handler used inline: the challenge must
// exist and must require exfil. The flag is not validated here — it is matched
// later at SubmitEvade time via HasExfil (a wrong value simply fails the gate),
// exactly as before.
//
// `user` and `flag` are expected pre-trimmed / pre-validated (non-empty) by the
// adapter, matching prior handler behaviour.
//
// The returned ExfilStatus is only meaningful when err == nil (standard Go
// convention: when err != nil the other return values are undefined). On a
// store error the status is reported as ExfilRecorded but the receipt was NOT
// persisted — callers must branch on err first and never trust the status
// when err is non-nil.
func (g *Grader) RecordExfil(user, cid, flag string) (ExfilStatus, error) {
	ch, ok := g.cat[cid]
	if !ok {
		return ExfilUnknownChallenge, nil
	}
	if !ch.RequireExfil {
		return ExfilNotRequired, nil
	}
	at := g.now().UTC().Format(time.RFC3339Nano)
	if err := g.store.RecordExfil(user, cid, flag, at); err != nil {
		return ExfilRecorded, err
	}
	return ExfilRecorded, nil
}
