package authpolicy

// The roster is ADR-0034 D2's identity table: the ONE place that decides which
// authenticated identity is which seat (workspace name). auth-policy reads it
// once at startup from ROSTER_FILE and refuses to start if the file is absent,
// empty or malformed; it never reloads (adding or revoking a row is a Secret
// swap plus a rolling restart).
//
// File shape:
//
//	seats:
//	  - seat: user1
//	  - seat: user2
//	    external: someone@partner.example   # optional, at most one
//
// The file is personal data once an `external` is present. It is never logged
// whole and never served: only its counts reach /healthz.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Qfour/falco-ctf-app/internal/identity"
)

// googleMailDomains are the only domains whose local part is folded (dots
// dropped, `+tag` dropped) and whose domain is unified to the first entry:
// Google treats those spellings as one mailbox. Every other domain is only
// lower-cased. The set is a pinned constant (ADR-0034 D11), not configuration.
var googleMailDomains = [...]string{"gmail.com", "googlemail.com"}

// GoogleMailDomains returns a copy of the folded-domain set (pinned by a test).
func GoogleMailDomains() []string { return append([]string(nil), googleMailDomains[:]...) }

// maxRosterBytes bounds the file read: a roster of a few hundred seats is a few
// tens of KiB; anything near this is a mistake, not a roster.
const maxRosterBytes = 1 << 20

// NormalizeEmail is the single email normaliser (ADR-0034 D2). It is applied to
// roster rows AND to every identity auth-policy receives, so the two sides can
// never disagree on spelling.
//
//   - plain printable ASCII only (anything else -> false, before case folding:
//     strings.ToLower maps U+212A KELVIN SIGN to 'k')
//   - lower-cased, exactly one '@', non-empty local part and domain, no empty
//     domain label
//   - for gmail.com / googlemail.com only: `+tag` and every '.' dropped from the
//     local part, domain unified to gmail.com. A local part that becomes empty
//     (`+x@` on a folded domain) is not an identity.
func NormalizeEmail(s string) (string, bool) { return normalizeEmail(s, googleMailDomains[:]) }

func normalizeEmail(s string, folded []string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !identity.IsPlainASCII(s) {
		return "", false
	}
	s = strings.ToLower(s)
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 {
		return "", false
	}
	local := s[:at]
	dom, err := identity.NormalizeDomain(s[at+1:])
	if err != nil {
		return "", false
	}
	for _, f := range folded {
		if dom == f {
			if i := strings.IndexByte(local, '+'); i >= 0 {
				local = local[:i]
			}
			local = strings.ReplaceAll(local, ".", "")
			if local == "" {
				return "", false
			}
			dom = folded[0]
			break
		}
	}
	return local + "@" + dom, true
}

// Roster is the validated, immutable identity table.
type Roster struct {
	domain   string
	folded   []string
	seats    map[string]struct{}
	external map[string]string // normalised external email -> seat
}

type rosterDoc struct {
	Seats []rosterRow `yaml:"seats"`
}

type rosterRow struct {
	Seat     string  `yaml:"seat"`
	External *string `yaml:"external"`
}

// LoadRoster reads and validates ROSTER_FILE. An error means the process must
// not start (fail-closed): there is no "no roster" mode.
func LoadRoster(path, domain string, admins []string) (*Roster, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("roster: ROSTER_FILE is not set")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("roster: open %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRosterBytes+1))
	if err != nil {
		return nil, fmt.Errorf("roster: read %s: %w", path, err)
	}
	if len(data) > maxRosterBytes {
		return nil, fmt.Errorf("roster: %s is larger than %d bytes", path, maxRosterBytes)
	}
	return ParseRoster(data, domain, admins)
}

// ParseRoster validates roster bytes against the expected email domain and the
// admin allowlist. Exported so handler tests can build a roster without a file.
func ParseRoster(data []byte, domain string, admins []string) (*Roster, error) {
	return parseRoster(data, domain, admins, googleMailDomains[:])
}

func parseRoster(data []byte, domain string, admins []string, folded []string) (*Roster, error) {
	cfg, err := identity.Validate(domain, admins, false)
	if err != nil {
		return nil, fmt.Errorf("roster: %w", err)
	}
	// Both directions of the admin overlap are checked on the NORMALISED
	// forms, so `Admin@x` and `admin@x` (or a folded external) cannot hide one.
	adminSet := make(map[string]struct{}, len(cfg.Admins))
	for _, a := range cfg.Admins {
		n, ok := normalizeEmail(a, folded)
		if !ok {
			return nil, fmt.Errorf("roster: ADMIN_EMAILS entry %q does not normalise", a)
		}
		adminSet[n] = struct{}{}
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc rosterDoc
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("roster: file is empty")
		}
		return nil, fmt.Errorf("roster: parse: %w", err)
	}
	var extra rosterDoc
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("roster: more than one YAML document")
	}
	if len(doc.Seats) == 0 {
		return nil, errors.New("roster: no seats")
	}

	r := &Roster{
		domain:   cfg.Domain,
		folded:   folded,
		seats:    make(map[string]struct{}, len(doc.Seats)),
		external: make(map[string]string),
	}
	for i, row := range doc.Seats {
		if !identity.IsPlainASCII(row.Seat) {
			return nil, fmt.Errorf("roster: seats[%d]: seat %q: %w", i, row.Seat, identity.ErrNotASCII)
		}
		if !validHost.MatchString(row.Seat) {
			return nil, fmt.Errorf("roster: seats[%d]: seat %q must match %s", i, row.Seat, validHost)
		}
		if _, dup := r.seats[row.Seat]; dup {
			return nil, fmt.Errorf("roster: seats[%d]: duplicate seat %q", i, row.Seat)
		}
		r.seats[row.Seat] = struct{}{}
		if _, hit := adminSet[identity.Canonical(row.Seat, cfg.Domain)]; hit {
			return nil, fmt.Errorf("roster: seat %q: %s is also in ADMIN_EMAILS", row.Seat, identity.Canonical(row.Seat, cfg.Domain))
		}
		if row.External == nil {
			continue
		}
		ext := *row.External
		if strings.TrimSpace(ext) == "" {
			return nil, fmt.Errorf("roster: seat %q: external is blank (omit the key instead)", row.Seat)
		}
		if !identity.IsPlainASCII(strings.TrimSpace(ext)) {
			return nil, fmt.Errorf("roster: seat %q: external: %w", row.Seat, identity.ErrNotASCII)
		}
		n, ok := normalizeEmail(ext, folded)
		if !ok {
			return nil, fmt.Errorf("roster: seat %q: external is not a usable email (shape, or an empty local part after normalisation)", row.Seat)
		}
		if n[strings.IndexByte(n, '@')+1:] == cfg.Domain {
			return nil, fmt.Errorf("roster: seat %q: external is in EXPECTED_EMAIL_DOMAIN %q; that domain is the seat namespace", row.Seat, cfg.Domain)
		}
		if _, hit := adminSet[n]; hit {
			return nil, fmt.Errorf("roster: seat %q: external is also in ADMIN_EMAILS", row.Seat)
		}
		if other, dup := r.external[n]; dup {
			return nil, fmt.Errorf("roster: seat %q: external duplicates seat %q's after normalisation", row.Seat, other)
		}
		r.external[n] = row.Seat
	}
	return r, nil
}

// Domain is the (normalised) EXPECTED_EMAIL_DOMAIN the roster was validated
// against and the canonical form is spelled with.
func (r *Roster) Domain() string { return r.domain }

// SeatCount / ExternalCount are the only facts about the roster that leave the
// process (via /healthz).
func (r *Roster) SeatCount() int     { return len(r.seats) }
func (r *Roster) ExternalCount() int { return len(r.external) }

// Resolve maps an authenticated identity to its seat. It returns ok=false for
// anything not in the table: an empty or malformed identity, an identity whose
// normalised local part is empty, a domain that is neither EXPECTED_EMAIL_DOMAIN
// nor a rostered external, or a `<x>@<EXPECTED_EMAIL_DOMAIN>` with x not a seat.
// There is no prefix, suffix or substring rule.
func (r *Roster) Resolve(rawEmail string) (seat string, ok bool) {
	if r == nil {
		return "", false
	}
	n, ok := normalizeEmail(rawEmail, r.folded)
	if !ok {
		return "", false
	}
	at := strings.IndexByte(n, '@')
	local, dom := n[:at], n[at+1:]
	if dom == r.domain {
		if _, in := r.seats[local]; in {
			return local, true
		}
		return "", false
	}
	if seat, in := r.external[n]; in {
		return seat, true
	}
	return "", false
}
