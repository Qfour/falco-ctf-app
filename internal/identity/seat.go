package identity

import "regexp"

// SeatPattern is the ONE definition of what a seat (a workspace / participant
// name such as "user7", the `<user>` in `<user>@<domain>`) may look like
// (app#440): lower-case letters, digits and "-", the first a letter or digit,
// at most 63 characters (a DNS label, since the seat is the first label of the
// workspace ingress host and the tail of its `ctf-<seat>` namespace).
//
// It is the string the OpenAPI specs repeat as `pattern`; a test holds every
// `pattern` of the three specs equal to the set of Go grammar definitions
// (internal/apispec/specparity, identifier_patterns_test.go), so a spec cannot
// drift from this without `make test` going red.
//
// Every Go user of the seat grammar imports this and keeps no copy: the
// scoreboard API (path `{user}` and the three request bodies), the
// /falco/events namespace parse, the Grader's slug gate and the boot-time stored
// -user count, auth-policy (the roster's seats and the `host` query parameter)
// and the e2e harness. Shell and Helm copies (Makefile `E2E_USER`, charts) cannot
// import Go and stay approximations.
const SeatPattern = `^[a-z0-9][a-z0-9-]{0,62}$`

var seatRE = regexp.MustCompile(SeatPattern)

// ValidSeat reports whether s is a seat name.
func ValidSeat(s string) bool { return seatRE.MatchString(s) }
