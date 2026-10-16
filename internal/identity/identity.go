// Package identity holds the pieces of the I8 identity contract (ADR-0034 D2 /
// D5 / D7) that BOTH the auth-policy and the scoreboard binaries must agree
// on: what a reserved domain is, how the canonical `<seat>@<domain>` form is
// spelled, and the startup check that keeps an external IdP from ever being
// able to produce either the canonical form or an admin email.
//
// It is stdlib-only on purpose (auth-policy's Dockerfile copies this directory
// by name, like internal/serverutil): the roster file parser and the email
// normaliser live in internal/authpolicy, because only auth-policy reads the
// roster. The scoreboard never sees anything but the canonical form.
package identity

import (
	"errors"
	"fmt"
	"strings"
)

// reservedLabels are the last DNS labels that no public registry can delegate
// (RFC 2606 / RFC 6761 / RFC 6762). An external IdP (Google) cannot hold a
// verified email whose domain ends in one of them, which is what makes
// "<seat>@<EXPECTED_EMAIL_DOMAIN>" and every ADMIN_EMAILS entry unforgeable
// from the IdP side (ADR-0034 D2, paired with oauth2-proxy rejecting
// unverified emails).
var reservedLabels = [...]string{"local", "test", "invalid", "example", "localhost"}

// ReservedLabels returns a copy of the reserved last-label set.
func ReservedLabels() []string { return append([]string(nil), reservedLabels[:]...) }

// ErrNotASCII is returned for any identity input that contains a non-ASCII
// byte. strings.ToLower folds some non-ASCII code points onto ASCII letters
// (U+212A KELVIN SIGN -> 'k'), so non-ASCII is rejected before any case
// folding, on the roster side and the request side alike.
var ErrNotASCII = errors.New("identity: non-ASCII or control character")

// IsPlainASCII reports whether s contains only printable ASCII (0x21-0x7e).
// Whitespace and control bytes are rejected too: an identity string with an
// embedded space or newline is never legitimate.
func IsPlainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// NormalizeDomain trims and lower-cases a bare domain and checks it is a
// plausible ASCII domain: no empty label (which also rejects a trailing dot),
// no '@'. It does NOT check reservation; see CheckReservedDomain.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSpace(d)
	if d == "" {
		return "", errors.New("domain is empty")
	}
	if !IsPlainASCII(d) {
		return "", fmt.Errorf("domain %q: %w", d, ErrNotASCII)
	}
	d = strings.ToLower(d)
	if strings.ContainsRune(d, '@') {
		return "", fmt.Errorf("domain %q contains '@'", d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return "", fmt.Errorf("domain %q has an empty label (trailing or doubled dot)", d)
		}
	}
	return d, nil
}

// CheckReservedDomain returns nil iff the LAST label of the (already
// normalised) domain is a reserved name. The label is compared exactly, so
// "evil-local" and "x.notlocal" are rejected while "ctf.local" and
// "partner.example" pass.
func CheckReservedDomain(domain string) error {
	i := strings.LastIndexByte(domain, '.')
	last := domain[i+1:] // i == -1 -> the whole string (a single-label domain)
	for _, r := range reservedLabels {
		if last == r {
			return nil
		}
	}
	return fmt.Errorf("domain %q: last label %q is not a reserved name (%s)", domain, last, strings.Join(reservedLabels[:], ", "))
}

// Canonical is the one spelling of a seat's identity that is allowed past
// auth-policy: "<seat>@<domain>".
func Canonical(seat, domain string) string { return seat + "@" + domain }

// NormalizeAdminEmails validates ADMIN_EMAILS and returns it lower-cased and
// de-blanked. Every entry must be plain ASCII, contain exactly one '@' with a
// non-empty local part, and have a domain whose last label is reserved: an
// admin email an external IdP could hold would let that IdP's user into the
// operator routes.
func NormalizeAdminEmails(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	// Errors name an entry by its position, never by its value: a mistyped
	// ADMIN_EMAILS element is often a real mailbox and the message ends up in a
	// pod log on every restart (ADR-0034 D3).
	for i, e := range raw {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !IsPlainASCII(e) {
			return nil, fmt.Errorf("ADMIN_EMAILS[%d]: %w", i, ErrNotASCII)
		}
		e = strings.ToLower(e)
		at := strings.IndexByte(e, '@')
		if at <= 0 || at != strings.LastIndexByte(e, '@') || at == len(e)-1 {
			return nil, fmt.Errorf("ADMIN_EMAILS[%d]: want exactly one '@' with a non-empty local part and domain", i)
		}
		// NormalizeDomain / CheckReservedDomain quote the domain they reject
		// (right for EXPECTED_EMAIL_DOMAIN, which is configuration). An admin
		// entry's domain is part of a mailbox, so neither error is passed on:
		// the entry is named by position and the defect by kind only.
		dom, err := NormalizeDomain(e[at+1:])
		if err != nil {
			return nil, fmt.Errorf("ADMIN_EMAILS[%d]: domain is not a plausible ASCII domain (empty label from a trailing or doubled dot)", i)
		}
		if err := CheckReservedDomain(dom); err != nil {
			return nil, fmt.Errorf("ADMIN_EMAILS[%d]: domain is not a reserved name", i)
		}
		out = append(out, e)
	}
	return out, nil
}

// Config is the validated identity configuration shared by auth-policy and
// the scoreboard.
type Config struct {
	// Domain is the normalised EXPECTED_EMAIL_DOMAIN. Empty only when the
	// caller allowed it (the scoreboard: empty means no self identity can ever
	// match, fail-closed).
	Domain string
	// Admins is the normalised ADMIN_EMAILS list.
	Admins []string
}

// Validate is the startup check ADR-0034 D2 / D5 put on both binaries.
// allowEmptyDomain is true for the scoreboard (V11: an empty domain makes self
// unmatchable) and false for auth-policy (it cannot resolve a seat without
// one).
func Validate(domain string, admins []string, allowEmptyDomain bool) (Config, error) {
	var cfg Config
	if strings.TrimSpace(domain) == "" {
		if !allowEmptyDomain {
			return Config{}, errors.New("EXPECTED_EMAIL_DOMAIN is empty")
		}
	} else {
		d, err := NormalizeDomain(domain)
		if err != nil {
			return Config{}, fmt.Errorf("EXPECTED_EMAIL_DOMAIN: %w", err)
		}
		if err := CheckReservedDomain(d); err != nil {
			return Config{}, fmt.Errorf("EXPECTED_EMAIL_DOMAIN: %w", err)
		}
		cfg.Domain = d
	}
	a, err := NormalizeAdminEmails(admins)
	if err != nil {
		return Config{}, err
	}
	cfg.Admins = a
	return cfg, nil
}
