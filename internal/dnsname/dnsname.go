// Package dnsname is the ONE definition of the RFC 1123 DNS name grammar the
// deployment accepts (ADR-0047, app#533): lower-case labels of 1 to 63 characters of
// letters, digits and "-" (the first and the last a letter or digit), joined by ".",
// at most 253 characters in all. No scheme, port, path, userinfo, trailing dot,
// upper-case letter or IPv6 literal.
//
// It is a leaf on purpose: standard library only, no package of this module. Its
// users are
//
//   - internal/ttydproxy: FrameAncestorsPattern composes Body (the host of the
//     FRAME_ANCESTORS source, ADR-0044 D2);
//   - the scoreboard's PORTAL_TTYD_SUFFIX start-up check (app#532, not yet): Valid;
//   - charts/ctf-user/deploy-user.sh: DNS_SUFFIX_PATTERN / DNS_SUFFIX_MAX_LEN, a shell
//     copy of Pattern / MaxLen that dnsname_test.go holds equal (it is the grammar of
//     --dns-suffix and --app-host).
//
// A new consumer imports this package; it does not spell the grammar again (the seat
// detector in internal/identity is red on a second copy of Label). Changing it changes
// --dns-suffix, --app-host and --frame-ancestors at once, so a narrowing is a paired
// PR in falco-ctf-platform too (ADR-0047 Consequences).
package dnsname

import "regexp"

// Label is one DNS label: 1 to 63 characters (the first, then up to 61 in the
// middle, then the last), the first and the last a letter or digit. It is the only
// place this module spells the grammar: the bound of 63 is the {0,61} here.
const Label = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`

// Body is one or more labels joined by ".", unanchored, for a grammar that embeds a
// host (ttydproxy.FrameAncestorsPattern).
const Body = Label + `(\.` + Label + `)*`

// Pattern is Body anchored: the whole string is a name. A regexp cannot count the
// whole, so a check of a name also compares its length with MaxLen (Valid does).
const Pattern = `^` + Body + `$`

// MaxLen is RFC 1123's limit on a whole name, in characters.
const MaxLen = 253

var re = regexp.MustCompile(Pattern)

// Valid reports whether s is a name of the grammar and at most MaxLen long. The
// empty string is not one.
func Valid(s string) bool { return len(s) <= MaxLen && re.MatchString(s) }
