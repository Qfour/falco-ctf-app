package identity

import "regexp"

// SeatPattern is the ONE Go definition of what a seat (a workspace / participant
// name such as "user7", the `<user>` in `<user>@<domain>`) may look like
// (app#440): lower-case letters, digits and "-", the first a letter or digit, at
// most 63 characters.
//
// Two things this is NOT:
//
//   - It is not the set of seats a deployment accepts. The grammar is wider than
//     what the deploy path can use (a seat becomes a Helm release name part and a
//     DNS label of the workspace host, which allow at most 53 characters and must
//     end in a letter or digit; this pattern allows 63 and a trailing "-"). The
//     scoreboard and auth-policy accept anything inside this pattern; whether to
//     tighten it to the deploy's set is app#480.
//   - It is not a Go-only matter. The seat grammar is part of the cross-repo
//     identity contract (ADR-0034 D2: the roster, the canonical
//     `<seat>@<EXPECTED_EMAIL_DOMAIN>` form, the workspace host). Changing
//     SeatPattern needs architect agreement and VP approval, and a paired PR in
//     falco-ctf-platform (its stand-up and roster tooling read the same shape).
//
// It is the string the OpenAPI specs repeat as `pattern`; a test holds every
// `pattern` of the three specs equal to the set of Go grammar definitions, with
// each grammar at exactly the expected number of sites per spec
// (internal/apispec/specparity, identifier_patterns_test.go).
//
// There is exactly one copy of the grammar outside Go that is checked against
// this definition: SEAT_PATTERN in charts/ctf-user/deploy-user.sh (it must stop a
// bad username before any kubectl / helm call, and cannot import Go). Two checks
// hold it equal: TestDeployUserShellPatternIsTheGoPattern pins its text to
// SeatPattern, and scripts/check-seat-grammar.sh runs the shared case table,
// internal/identity/testdata/seat-cases.tsv, through the script (ValidSeat reads
// the same table: TestValidSeat_SharedCaseTable). Platform's roster tooling (a
// private repo) reads the same table in its paired PR. The grammar is therefore
// changed in one go: SeatPattern, the table's rows, SEAT_PATTERN, the three
// specs' `pattern` (make gen) and platform's readers, in the same PR group.
// The `make e2e-serve AS=` check in the Makefile is only an approximation and is
// not registered with the table; the e2e harness re-checks the name in Go.
//
// Every Go user of the seat grammar imports this and keeps no copy: the
// scoreboard API (path `{user}` and the three request bodies), the /falco/events
// namespace parse, the Grader's slug gate and the boot-time stored-user count,
// auth-policy (the roster's seats and the `host` query parameter) and the e2e
// harness. users_test.go checks that (the files import this, and no other
// non-test Go file spells the pattern).
const SeatPattern = `^[a-z0-9][a-z0-9-]{0,62}$`

var seatRE = regexp.MustCompile(SeatPattern)

// ValidSeat reports whether s is a seat name. Being one says nothing about who
// sent it: whether a caller is proven is each route's authorization
// (x-ctf-authz), not this predicate.
func ValidSeat(s string) bool { return seatRE.MatchString(s) }
