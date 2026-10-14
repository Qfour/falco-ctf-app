package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// UserPattern is the username shape the scoreboard accepts. It mirrors
// validUser in internal/scoreboard/api/api.go; seed_test.go reads that file and
// fails when the two drift. `make e2e-serve AS=` accepts nothing else, so the
// identity e-mail it builds can never be a surprising one.
var UserPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// IdentityDomain is the reserved-TLD domain of every synthetic identity
// (ADR-0031 V8: a `.test` name, so no IdP can hold such an address). It is
// also the child's EXPECTED_EMAIL_DOMAIN (ADR-0034 S2), under which
// "<user>@<IdentityDomain>" is exactly user's own identity.
const IdentityDomain = "e2e.test"

// TtydSuffix is the PORTAL_TTYD_SUFFIX test value: the portal builds each
// caller's terminal iframe as https://<user>.<TtydSuffix>.
const TtydSuffix = "e2e.test"

// EmailFor returns the synthetic identity e-mail of user, or an error when user
// is not a valid scoreboard username.
func EmailFor(user string) (string, error) {
	if !UserPattern.MatchString(user) {
		return "", fmt.Errorf("harness: %q is not a valid username (want %s)", user, UserPattern)
	}
	return user + "@" + IdentityDomain, nil
}

// Plan is the mission sequence and the per-mission facts a seed needs, read
// from the repository's real catalog at run time: a rule name or a flag is
// never copied into a test (ADR-0031 D3). FLAGS_FILE is never involved, so the
// flags are the public FALCO{dev-...} placeholders.
type Plan struct {
	Order   []string
	Catalog catalog.Catalog
	// Journeys is the journey.yaml content the child serves (hint texts are
	// read from here by a scenario, never copied into it).
	Journeys catalog.Journeys
}

// LoadPlan reads the catalog the scoreboard child will load, the way
// cmd/scoreboard does (catalog.LoadScored, then LoadJourneys over its catalog).
func LoadPlan(challengesDir, scenarioFile string) (*Plan, error) {
	scored, err := catalog.LoadScored(challengesDir, scenarioFile, "")
	if err != nil {
		return nil, err
	}
	journeys, err := catalog.LoadJourneys(challengesDir, scored.Catalog)
	if err != nil {
		return nil, err
	}
	return &Plan{Order: scored.Order, Catalog: scored.Catalog, Journeys: journeys}, nil
}

// Seeder puts a scoreboard child into a state using its HTTP surface only:
// POST /falco/events and POST /api/challenges/{cid}/submit (ADR-0031 D3). It
// talks to the child directly, not through the Proxy, so a seed never appears
// in the request log a scenario judges.
//
// Each request has the shape its production caller gives it (see caller), not
// one shape for all: a seed that sent the ingress's identity header on the
// webhook would exercise a path production never takes, and the scoreboard
// refuses exactly that path (app#334: any X-Auth-Request-* header on
// /falco/events or /internal/* is the browser path and gets 403).
type Seeder struct {
	base   string
	email  string
	client *http.Client
	plan   *Plan
}

// NewSeeder returns a Seeder for up (the scoreboard child, or in a unit test a
// recording Site). email is the X-Auth-Request-Email it sends on its
// self-scope reads (GET .../journey) and nowhere else: the webhook and the
// submit go out without any X-Auth-Request-* header.
func NewSeeder(up Upstream, email string, plan *Plan) *Seeder {
	return &Seeder{base: "http://" + up.upstreamAddr(), email: email, client: &http.Client{}, plan: plan}
}

// caller is who sends a request in production, which decides its headers.
type caller int

const (
	// asFalcosidekick: POST /falco/events the way falcosidekick sends it over
	// the cluster-internal Service — a JSON body and no X-Auth-Request-*
	// header (no ingress is in that path).
	asFalcosidekick caller = iota
	// asCollector: POST .../submit the way the collector forwards a
	// participant's curl (the submit's primary path, falco-api) — a JSON body,
	// no X-Auth-Request-* header; the user is the one the body claims.
	asCollector
	// asIngress: a self-scope read as the ingress delivers it — the identity
	// header set to the seeder's e-mail (the scoreboard refuses the read
	// without one).
	asIngress
)

func (s *Seeder) do(ctx context.Context, who caller, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, rd)
	if err != nil {
		return err
	}
	if who == asIngress {
		req.Header.Set(IdentityHeader, s.email)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decode: %w (%s)", method, path, err, raw)
		}
	}
	return nil
}

// FireRule delivers one Falco event for user's workspace in the shape
// falcosidekick sends (asFalcosidekick: JSON, no X-Auth-Request-* header) with
// the fields ingest.go's filter reads: ns ctf-<user>, pod workspace, a
// falco-ctf/challenge image, priority Notice or above. No webhook secret: the
// child runs with the secret mode off (FALCO_WEBHOOK_SHARED_SECRET and
// WEBHOOK_SECRET_MODE are forbidden in its env).
func (s *Seeder) FireRule(ctx context.Context, user, rule string) error {
	ev := map[string]any{
		"rule":     rule,
		"priority": "Notice",
		"output_fields": map[string]any{
			"k8s.ns.name":                "ctf-" + user,
			"k8s.pod.name":               "workspace",
			"container.image.repository": "falco-ctf/challenge",
		},
	}
	var res map[string]any
	if err := s.do(ctx, asFalcosidekick, http.MethodPost, "/falco/events", ev, &res); err != nil {
		return err
	}
	if ignored, _ := res["ignored"].(bool); ignored {
		return fmt.Errorf("falco event for rule %q was ignored: %v", rule, res)
	}
	return nil
}

// Submit posts a flag for cid on behalf of user, the way the collector forwards
// a participant's curl (asCollector), and returns the verdict body.
func (s *Seeder) Submit(ctx context.Context, user, cid, flag string) (map[string]any, error) {
	var res map[string]any
	err := s.do(ctx, asCollector, http.MethodPost, "/api/challenges/"+cid+"/submit", map[string]any{"user": user, "flag": flag}, &res)
	return res, err
}

// Journey reads GET /api/users/{user}/journey (optionally ?mission=) as the
// ingress delivers it (asIngress: with the seeder's identity).
func (s *Seeder) Journey(ctx context.Context, user, mission string) (map[string]any, error) {
	path := "/api/users/" + user + "/journey"
	if mission != "" {
		path += "?mission=" + mission
	}
	var res map[string]any
	err := s.do(ctx, asIngress, http.MethodGet, path, nil, &res)
	return res, err
}

// SolveBefore solves, in scenario order, every mission before cid, so that cid
// becomes user's current mission. Triggers are solved by firing their expected
// rules; evades by firing the rules their positive proof asks for (if any) and
// submitting the catalog's flag.
func (s *Seeder) SolveBefore(ctx context.Context, user, cid string) error {
	idx := -1
	for i, id := range s.plan.Order {
		if id == cid {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("mission %q is not in the scenario %v", cid, s.plan.Order)
	}
	for _, id := range s.plan.Order[:idx] {
		ch := s.plan.Catalog[id]
		switch ch.Type {
		case "trigger":
			for _, rule := range ch.ExpectedRules {
				if err := s.FireRule(ctx, user, rule); err != nil {
					return fmt.Errorf("solve %s: %w", id, err)
				}
			}
		case "evade":
			if ch.RequireExfil {
				return fmt.Errorf("solve %s: an exfil-required mission cannot be seeded over HTTP alone", id)
			}
			if ch.RequireExpectedRuleFire {
				for _, rule := range ch.ExpectedRules {
					if err := s.FireRule(ctx, user, rule); err != nil {
						return fmt.Errorf("solve %s: %w", id, err)
					}
				}
			}
			res, err := s.Submit(ctx, user, id, ch.ExpectedFlag)
			if err != nil {
				return fmt.Errorf("solve %s: %w", id, err)
			}
			if solved, _ := res["solved"].(bool); !solved {
				return fmt.Errorf("solve %s: submit was not accepted: %v", id, res)
			}
		default:
			return fmt.Errorf("solve %s: cannot seed a %q mission", id, ch.Type)
		}
	}
	return s.expectCurrent(ctx, user, cid)
}

func (s *Seeder) expectCurrent(ctx context.Context, user, cid string) error {
	j, err := s.Journey(ctx, user, "")
	if err != nil {
		return err
	}
	if cur, _ := j["current"].(string); cur != cid {
		return fmt.Errorf("after seeding, current is %q, want %q", cur, cid)
	}
	return nil
}

// TaintCurrent fires a forbidden rule of cid (the user's current mission), the
// way a participant's workspace would, so the attempt is dirty.
func (s *Seeder) TaintCurrent(ctx context.Context, user, cid string) error {
	ch := s.plan.Catalog[cid]
	if len(ch.ForbiddenRules) == 0 {
		return fmt.Errorf("%s has no forbidden rule to fire", cid)
	}
	if err := s.FireRule(ctx, user, ch.ForbiddenRules[0]); err != nil {
		return err
	}
	j, err := s.Journey(ctx, user, "")
	if err != nil {
		return err
	}
	detail, _ := j["detail"].(map[string]any)
	if dirty, _ := detail["dirty"].(bool); !dirty {
		return fmt.Errorf("after firing %q the attempt of %s is not dirty: %v", ch.ForbiddenRules[0], cid, detail)
	}
	return nil
}

// The seeds `make e2e-serve SEED=` and the scenarios share (ADR-0031 D3: one
// place, so a change to how a mission is started is fixed once).
const (
	SeedFresh   = "fresh"
	SeedClean05 = "clean-05"
	SeedDirty05 = "dirty-05"
	mission05   = "05-silent-search"
)

var seeds = map[string]func(ctx context.Context, s *Seeder, user string) error{
	SeedFresh: func(context.Context, *Seeder, string) error { return nil },
	SeedClean05: func(ctx context.Context, s *Seeder, user string) error {
		return s.SolveBefore(ctx, user, mission05)
	},
	SeedDirty05: func(ctx context.Context, s *Seeder, user string) error {
		if err := s.SolveBefore(ctx, user, mission05); err != nil {
			return err
		}
		return s.TaintCurrent(ctx, user, mission05)
	},
}

// SeedNames lists the seeds, sorted.
func SeedNames() []string {
	names := make([]string, 0, len(seeds))
	for n := range seeds {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Seed applies the named seed for user.
func (s *Seeder) Seed(ctx context.Context, name, user string) error {
	fn, ok := seeds[name]
	if !ok {
		return fmt.Errorf("unknown seed %q (have %s)", name, strings.Join(SeedNames(), ", "))
	}
	if !UserPattern.MatchString(user) {
		return errors.New("invalid user")
	}
	return fn(ctx, s, user)
}
