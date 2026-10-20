package identity

import "regexp"

// SeatPattern is the ONE Go definition of what a seat (a workspace / participant
// name such as "user7", the `<user>` in `<user>@<domain>`) may look like: 1 to 53
// characters of lower-case letters, digits and "-", the first and the last a
// letter or digit. ADR-0042 is the canonical statement (it replaces the one
// sentence of ADR-0034 D2 that gave the previous, wider grammar; app#440 made
// this the single Go definition, app#480 narrowed it).
//
// The grammar IS the set of seats a deployment can use: a seat is the Helm
// release name (at most 53 characters, starting and ending with a letter or
// digit), the `ctf-<seat>` namespace, the label values and the first label of
// the workspace host, and 53 characters / alphanumeric ends is the strictest of
// them. A name outside it cannot be deployed, so it is not a seat. The
// scoreboard and auth-policy accept nothing outside this pattern.
//
// It is not a Go-only matter. The seat grammar is part of the cross-repo
// identity contract (ADR-0034 D2: the roster, the canonical
// `<seat>@<EXPECTED_EMAIL_DOMAIN>` form, the workspace host). Changing
// SeatPattern needs architect agreement and VP approval, and a paired PR in
// falco-ctf-platform (its stand-up and roster tooling read the same shape).
//
// It is the string the OpenAPI specs repeat as `pattern`; a test holds every
// `pattern` of the three specs equal to the set of Go grammar definitions, with
// each grammar at exactly the expected number of sites per spec
// (internal/apispec/specparity, identifier_patterns_test.go). A render test
// (internal/apispec/ingressparity, seat_render_test.go) holds the grammar to the
// names the deploy builds from a seat: it renders charts/ctf-user for the edges
// of this set and checks the namespace, the label values and the host.
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
const SeatPattern = `^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$`

var seatRE = regexp.MustCompile(SeatPattern)

// ValidSeat reports whether s is a seat name. Being one says nothing about who
// sent it: whether a caller is proven is each route's authorization
// (x-ctf-authz), not this predicate.
func ValidSeat(s string) bool { return seatRE.MatchString(s) }
