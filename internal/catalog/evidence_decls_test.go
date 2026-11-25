package catalog_test

import (
	"slices"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// ADR-0056 amendment 26 (A7-x PR 3): `investigate.evidence.shares` and
// `investigate.evidence.timeline`, the public declarations that B14 and B15 (internal/edition)
// hold the templates to. The load checks the grammar of the ids, that a declaration does not
// name the challenge itself, that a share names a file and is not declared twice, and that the
// challenge named is an investigate challenge of the catalog. A challenge with no declaration
// loads as before.

const (
	evX = "50-ev-x"
	evY = "51-ev-y"
)

// evWith is an investigate challenge whose `evidence:` block is the mount and then the extra lines
// (indented under `evidence:`).
func evWith(mount, extra string) string {
	return "type: " + catalog.TypeInvestigate + "\ninvestigate:\n  evidence:\n    mountDir: " + mount + "\n" + extra + "  questions:\n" + invHexQ
}

func TestLoad_EvidenceDecls_Valid(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, evX, evWith("/srv/ev-x", ""))
	writeChallenge(t, dir, evY, evWith("/srv/ev-y",
		"    shares:\n      - with: "+evX+"\n        file: gateway.log\n      - with: "+evX+"\n        file: note.txt\n"+
			"    timeline: "+evX+"\n"))
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ev := cat[evY].Investigate.Evidence
	want := []catalog.EvidenceShare{{With: evX, File: "gateway.log"}, {With: evX, File: "note.txt"}}
	if !slices.Equal(ev.Shares, want) || ev.Timeline != evX || ev.MountDir != "/srv/ev-y" {
		t.Errorf("evidence = %+v, want the shares %v, the timeline %s and the mount", ev, want, evX)
	}
	// No declaration: the zero values, as before the keys existed.
	if x := cat[evX].Investigate.Evidence; len(x.Shares) != 0 || x.Timeline != "" {
		t.Errorf("a challenge with no declaration has %+v", x)
	}
	// The flow form loads too.
	dir = t.TempDir()
	writeChallenge(t, dir, evX, evWith("/srv/ev-x", ""))
	writeChallenge(t, dir, evY, evWith("/srv/ev-y", "    shares: [{with: "+evX+", file: gateway.log}]\n"))
	if _, err := catalog.Load(dir); err != nil {
		t.Errorf("the flow form of shares: Load: %v", err)
	}
}

// Every one of these is a load failure, for the reason named.
func TestLoad_EvidenceDecls_Rejected(t *testing.T) {
	share := func(with, file string) string {
		return "    shares:\n      - with: " + with + "\n        file: " + file + "\n"
	}
	trigger := "type: trigger\nexpectedRules: [r]\n"
	cases := []struct {
		name  string
		other string // the yaml of evX
		y     string // the extra lines of evY's evidence block
		want  string
	}{
		{"an unknown key in a share", evWith("/srv/ev-x", ""), "    shares:\n      - with: " + evX + "\n        file: a.log\n        mode: copy\n", "field mode not found"},
		{"an unknown key under evidence", evWith("/srv/ev-x", ""), "    shared: " + evX + "\n", "field shared not found"},
		{"shares is not a list", evWith("/srv/ev-x", ""), "    shares: " + evX + "\n", "investigate block"},
		{"a share outside the id grammar", evWith("/srv/ev-x", ""), share("Ev-X", "a.log"), "outside the challenge-id grammar"},
		{"a share with the challenge itself", evWith("/srv/ev-x", ""), share(evY, "a.log"), "names the challenge itself"},
		{"a share with no file", evWith("/srv/ev-x", ""), "    shares:\n      - with: " + evX + "\n", "file must not be empty"},
		{"a share with no with", evWith("/srv/ev-x", ""), "    shares:\n      - file: a.log\n", "outside the challenge-id grammar"},
		{"a share declared twice", evWith("/srv/ev-x", ""), share(evX, "a.log") + "      - with: " + evX + "\n        file: a.log\n", "declared already"},
		{"a share with a challenge not in the catalog", evWith("/srv/ev-x", ""), share("52-ev-none", "a.log"), "not an investigate challenge of the catalog"},
		{"a share with a challenge of another type", trigger, share(evX, "a.log"), "not an investigate challenge of the catalog"},
		{"a timeline outside the id grammar", evWith("/srv/ev-x", ""), "    timeline: ev x\n", "outside the challenge-id grammar"},
		{"a timeline of the challenge itself", evWith("/srv/ev-x", ""), "    timeline: " + evY + "\n", "names the challenge itself"},
		{"a timeline of a challenge not in the catalog", evWith("/srv/ev-x", ""), "    timeline: 52-ev-none\n", "not an investigate challenge of the catalog"},
		{"a timeline of a challenge of another type", trigger, "    timeline: " + evX + "\n", "not an investigate challenge of the catalog"},
		{"a timeline that is a list", evWith("/srv/ev-x", ""), "    timeline: [" + evX + "]\n", "investigate block"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeChallenge(t, dir, evX, c.other)
			writeChallenge(t, dir, evY, evWith("/srv/ev-y", c.y))
			_, err := catalog.Load(dir)
			wantLoadError(t, err, c.want)
		})
	}
}

// A timeline is a star (the review's R4#1): the challenge a timeline names declares none itself.
// A chain and a cycle are refused; two challenges that name one root are accepted.
func TestLoad_EvidenceDecls_TimelineIsAStar(t *testing.T) {
	const evZ = "52-ev-z"
	tl := func(cid string) string {
		return "    timeline: " + cid + "\n"
	}
	cases := []struct {
		name       string
		x, y, z    string // the extra lines of each challenge's evidence block
		wantRefuse bool
	}{
		{"a chain z -> y -> x", "", tl(evX), tl(evY), true},
		{"a cycle x -> y -> x", tl(evY), tl(evX), "", true},
		{"two challenges that name one root", "", tl(evX), tl(evX), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeChallenge(t, dir, evX, evWith("/srv/ev-x", c.x))
			writeChallenge(t, dir, evY, evWith("/srv/ev-y", c.y))
			writeChallenge(t, dir, evZ, evWith("/srv/ev-z", c.z))
			_, err := catalog.Load(dir)
			if !c.wantRefuse {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			wantLoadError(t, err, "a timeline is a star")
		})
	}
}

// The real tree: 51-nimbus-desk-egress declares what it shares with 50-nimbus-desk-triage, and the
// catalog loads it. The declaration is the fact B14 and B15 are held to (internal/edition).
func TestLoad_EvidenceDecls_TheRealTree(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	const a, b = "50-nimbus-desk-triage", "51-nimbus-desk-egress"
	ch, ok := cat[b]
	if !ok || ch.Investigate == nil {
		t.Fatalf("%s is not an investigate challenge of the tree", b)
	}
	ev := ch.Investigate.Evidence
	if want := []catalog.EvidenceShare{{With: a, File: "egress-gateway.log"}}; !slices.Equal(ev.Shares, want) || ev.Timeline != a {
		t.Errorf("%s: shares %v, timeline %q; want %v and %q", b, ev.Shares, ev.Timeline, want, a)
	}
}
