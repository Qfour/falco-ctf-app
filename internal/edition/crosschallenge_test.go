package edition_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

// ADR-0056 D10 B13 to B16 (amendment 26, amendment 28's limits; A7-x PR 3) on a synthetic scope
// of two investigate challenges: cxA, and cxB, which declares that it shares cxA's gateway.log
// (B14) and cxA's timeline (B15). The fixture passes every rule; each case breaks one thing and
// is refused by the rule it breaks, and by no message that holds a value or a time. Every value
// is a placeholder.

const (
	cxA    = "50-cx-a"
	cxB    = "51-cx-b"
	cxBase = "2001-01-01T00:00:00Z"
	// cxShared is the file both templates have, byte for byte, with no mark.
	cxShared = "2001-01-01T00:20:00Z gateway verdict=deny dst=192.0.2.9:443 dst_name=-\n" +
		"2001-01-01T00:21:00Z gateway verdict=allow dst=192.0.2.10:443 dst_name=mirror.example\n"
	// cxProse is a paragraph with no time and no answer, for the near copies of B14.
	cxProse = "The responder copied the notes of the shift into this file before the hand over. " +
		"Every line is a remark of the person on call, written in the order the remarks were made, " +
		"and nothing in it was checked against the records of the cluster at the time.\n"
)

// cxSecrets are the values of the fixture's answers and its literal times: none may be in a message.
var cxSecrets = []string{
	"2001-01-01T00:03:00Z", "2001-01-01T00:04:00Z", "a1b2c3d4e5f6", "b1b2c3d4e5f6", "operator-a", "operator-b",
	"files-07.example", "files-11.example", "2001-01-01T00:15:00Z", "2001-01-01T00:20:00Z", "2001-01-01T00:21:00Z",
}

func cxI64(v int64) *int64 {
	return &v
}

// cxFix is the scope that every rule accepts.
func cxFix() map[string]*edition.CrossChallenge {
	aEvents := func(when, who, tag string) string {
		return "shell started at " + when + " by " + who + " tag " + tag + "\n2001-01-01T00:15:00Z second shell on node-a\n"
	}
	bDNS := func(host string) string {
		return "2001-01-01T00:15:00Z query from pod-b resolved " + host + "\n"
	}
	a := &edition.CrossChallenge{
		Questions: []catalog.Question{
			{ID: "when", Format: answerformat.Timestamp, Params: answerformat.Params{WindowSeconds: cxI64(600)}, Attempts: 5},
			{ID: "tag", Format: answerformat.HexID, Params: answerformat.Params{Length: ip(12)}, Attempts: 5},
			{ID: "who", Format: answerformat.Name, Attempts: 5},
		},
		Spec: &edition.Spec{Time: edition.SpecTime{Base: cxBase}, Slots: []edition.Slot{
			{Name: "when", Role: edition.RoleAnswer, Question: "when", Window: &edition.Window{From: cxI64(0), To: cxI64(600)}},
			{Name: "tag", Role: edition.RoleAnswer, Question: "tag"},
			{Name: "who", Role: edition.RoleAnswer, Question: "who"},
		}},
		Template: []edition.BundleFile{
			{Name: "events.log", Data: []byte(aEvents("{{ctf:when}}", "{{ctf:who}}", "{{ctf:tag}}"))},
			{Name: "gateway.log", Data: []byte(cxShared)},
		},
		Bundles: []*edition.Bundle{
			{Seat: "seat-a", CID: cxA, Files: []edition.BundleFile{
				{Name: "events.log", Data: []byte(aEvents("2001-01-01T00:03:00Z", "operator-a", "a1b2c3d4e5f6"))},
				{Name: "gateway.log", Data: []byte(cxShared)},
			}},
			{Seat: "seat-b", CID: cxA, Files: []edition.BundleFile{
				{Name: "events.log", Data: []byte(aEvents("2001-01-01T00:04:00Z", "operator-b", "b1b2c3d4e5f6"))},
				{Name: "gateway.log", Data: []byte(cxShared)},
			}},
		},
		Answers: edition.SeatAnswers{
			"seat-a": {"when": "2001-01-01T00:03:00Z", "tag": "a1b2c3d4e5f6", "who": "operator-a"},
			"seat-b": {"when": "2001-01-01T00:04:00Z", "tag": "b1b2c3d4e5f6", "who": "operator-b"},
		},
	}
	b := &edition.CrossChallenge{
		Questions: []catalog.Question{{ID: "host", Format: answerformat.Name, Attempts: 5}},
		Evidence: catalog.Evidence{
			MountDir: "/srv/ev-b",
			Shares:   []catalog.EvidenceShare{{With: cxA, File: "gateway.log"}},
			Timeline: cxA,
		},
		Spec: &edition.Spec{Time: edition.SpecTime{Base: cxBase}, Slots: []edition.Slot{
			{Name: "host", Role: edition.RoleAnswer, Question: "host"},
		}},
		Template: []edition.BundleFile{
			{Name: "dns.log", Data: []byte(bDNS("{{ctf:host}}"))},
			{Name: "gateway.log", Data: []byte(cxShared)},
		},
		Bundles: []*edition.Bundle{
			{Seat: "seat-a", CID: cxB, Files: []edition.BundleFile{
				{Name: "dns.log", Data: []byte(bDNS("files-07.example"))},
				{Name: "gateway.log", Data: []byte(cxShared)},
			}},
			{Seat: "seat-b", CID: cxB, Files: []edition.BundleFile{
				{Name: "dns.log", Data: []byte(bDNS("files-11.example"))},
				{Name: "gateway.log", Data: []byte(cxShared)},
			}},
		},
		Answers: edition.SeatAnswers{
			"seat-a": {"host": "files-07.example"},
			"seat-b": {"host": "files-11.example"},
		},
	}
	return map[string]*edition.CrossChallenge{cxA: a, cxB: b}
}

// cxFile is the file of the list named name (the test fails when there is none).
func cxFile(t *testing.T, files []edition.BundleFile, name string) *edition.BundleFile {
	t.Helper()
	for i := range files {
		if files[i].Name == name {
			return &files[i]
		}
	}
	t.Fatalf("no file %s", name)
	return nil
}

// cxNoSecret fails if a message of err holds a value or a literal time of the fixture.
func cxNoSecret(t *testing.T, what string, err error) {
	t.Helper()
	for _, text := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		for _, s := range cxSecrets {
			if strings.Contains(text, s) {
				t.Errorf("%s: a message holds a value or a time of the fixture (%q): %q", what, s, text)
			}
		}
	}
}

func TestCrossChallenge_TheFixturePasses(t *testing.T) {
	rep, err := edition.CheckCrossChallenge(cxFix())
	if err != nil {
		t.Fatalf("the fixture is refused: %v", err)
	}
	// It compared something of every rule: the two ordered pairs of each seat, the declared
	// file, the pairs of files that are not declared, the timeline and the answer window.
	want := edition.CrossReport{AnswerPairs: 4, Shared: 1, FilePairs: 3, Timelines: 1, Windows: 1}
	if rep != want {
		t.Errorf("report %+v, want %+v", rep, want)
	}
}

// Each case breaks one thing of the fixture, and the check refuses it by that rule only.
func TestCrossChallenge_EachDefectIsRefusedByItsRule(t *testing.T) {
	appendTo := func(f *edition.BundleFile, text string) {
		f.Data = append(slices.Clone(f.Data), []byte(text)...)
	}
	cases := []struct {
		name  string
		rule  string
		apply func(t *testing.T, chs map[string]*edition.CrossChallenge)
	}{
		// B13
		{"an answer of A is in B's bundle of the same seat", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Bundles[0].Files, "dns.log"), "remark by operator-a\n")
		}},
		{"an answer of B is in A's bundle of the same seat", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxA].Bundles[1].Files, "events.log"), "link files-11.example\n")
		}},
		{"a hexid answer of A is in B's bundle in capitals (folded as grading accepts it)", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Bundles[0].Files, "dns.log"), "trace A1B2C3D4E5F6\n")
		}},
		{"a timestamp answer of A is in B's bundle with +00:00 (folded as grading accepts it)", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Bundles[1].Files, "dns.log"), "seen 2001-01-01T00:04:00+00:00\n")
		}},
		{"an answer is empty", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxA].Answers["seat-a"]["who"] = ""
		}},
		{"a bundle of another challenge is given", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxB].Bundles[1].CID = cxA
		}},
		{"no seat has both a challenge's answers and another's bundle", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxA].Bundles, chs[cxB].Bundles = nil, nil
		}},
		{"a challenge without its inputs", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs["52-cx-c"] = nil
		}},
		// B14
		{"one byte of the declared file differs on one side", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			f := cxFile(t, chs[cxB].Template, "gateway.log")
			f.Data = []byte(strings.Replace(cxShared, "deny", "denY", 1))
		}},
		{"the declared file holds a slot mark on both sides", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			marked := []byte(strings.Replace(cxShared, "mirror.example", "{{ctf:host}}", 1))
			cxFile(t, chs[cxA].Template, "gateway.log").Data = marked
			cxFile(t, chs[cxB].Template, "gateway.log").Data = marked
		}},
		{"the declaration is removed", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxB].Evidence.Shares = nil
		}},
		{"the declared file is not in A's template", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxA].Template = slices.DeleteFunc(chs[cxA].Template, func(f edition.BundleFile) bool { return f.Name == "gateway.log" })
		}},
		{"the declared file is outside B2's grammar", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxB].Evidence.Shares = append(chs[cxB].Evidence.Shares, catalog.EvidenceShare{With: cxA, File: "../gateway.log"})
		}},
		{"a copy one byte off under another name, not declared", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxA].Template = append(chs[cxA].Template, edition.BundleFile{Name: "notes.txt", Data: []byte(cxProse)})
			chs[cxB].Template = append(chs[cxB].Template, edition.BundleFile{Name: "memo.txt", Data: []byte(strings.Replace(cxProse, "copied", "Copied", 1))})
		}},
		{"a byte-identical copy under another name", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxB].Template = append(chs[cxB].Template, edition.BundleFile{Name: "gateway-copy.log", Data: []byte(cxShared)})
		}},
		// B15
		{"a literal time of A is moved and B is not", edition.RuleCrossTimeline, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			f := cxFile(t, chs[cxA].Template, "events.log")
			f.Data = []byte(strings.Replace(string(f.Data), "00:15:00Z", "00:15:01Z", 1))
		}},
		{"B has a literal time that A does not have", edition.RuleCrossTimeline, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Template, "dns.log"), "2001-01-01T00:40:00Z query from pod-b resolved {{ctf:host}}\n")
		}},
		// B16
		{"time.base moves the window over the literal times", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			s := *chs[cxA].Spec
			s.Time.Base = "2001-01-01T00:14:00Z"
			chs[cxA].Spec = &s
		}},
		{"a literal time in the window, in A's template", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxA].Template, "events.log"), "2001-01-01T00:05:00Z health check on node-a\n")
		}},
		{"the first second of the window is in it (half-open: from is in)", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxA].Template, "events.log"), "2001-01-01T00:00:00Z node-a booted\n")
		}},
		// A word outside every mark that is an RFC 3339 time in another spelling: refused (B16),
		// in A (an answer window, no timeline) and in B (a timeline, no answer window) alike. The
		// times are outside A's window, so only the spelling is refused.
		{"an RFC 3339 time with +00:00", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxA].Template, "events.log"), "seen 2001-01-01T00:45:00+00:00 on node-a\n")
		}},
		{"an RFC 3339 time with a fraction of a second", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxA].Template, "events.log"), "seen 2001-01-01T00:45:00.5Z on node-a\n")
		}},
		{"an RFC 3339 time with +09:00", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Template, "dns.log"), "seen 2001-01-01T09:45:00+09:00 by pod-b\n")
		}},
		{"an RFC 3339 time with a lower-case z", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Template, "dns.log"), "seen 2001-01-01T00:45:00z by pod-b\n")
		}},
		{"an RFC 3339 time with a lower-case t", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxA].Template, "events.log"), "seen 2001-01-01t00:45:00Z on node-a\n")
		}},
		{"no edition.yaml", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[cxB].Spec = nil
		}},
		{"a template with a mark outside the grammar", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			appendTo(cxFile(t, chs[cxB].Template, "dns.log"), "broken {{ctf:\n")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chs := cxFix()
			c.apply(t, chs)
			_, err := edition.CheckCrossChallenge(chs)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := rules(err); !slices.Contains(got, c.rule) {
				t.Errorf("rules %v, want %s among them: %v", got, c.rule, err)
			}
			cxNoSecret(t, c.name, err)
		})
	}
}

// A time in B's template that lies in A's answer window, and that A's template does not have, is
// refused twice: by B15 (A does not have it) and by B16 (B shares A's timeline, so A's window holds
// B's literal times too; A's own template has none in it).
func TestCrossChallenge_ATimeOfBInTheWindowOfAIsRefusedByB16(t *testing.T) {
	chs := cxFix()
	f := cxFile(t, chs[cxB].Template, "dns.log")
	f.Data = append(slices.Clone(f.Data), []byte("2001-01-01T00:09:59Z query from pod-b resolved {{ctf:host}}\n")...)
	_, err := edition.CheckCrossChallenge(chs)
	if got := rules(err); !slices.Equal(got, []string{edition.RuleCrossTimeline, edition.RuleCrossWindow}) {
		t.Errorf("rules %v, want B15 and B16: %v", got, err)
	}
}

// The edges of the rules: what they do not compare (the ADR's own bounds), each one a fixture
// that is accepted.
func TestCrossChallenge_WhatIsNotCompared(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(chs map[string]*edition.CrossChallenge)
		check func(t *testing.T, rep edition.CrossReport)
	}{
		{"a declaration of a challenge outside the scope", func(chs map[string]*edition.CrossChallenge) {
			delete(chs, cxA)
		}, func(t *testing.T, rep edition.CrossReport) {
			if rep.Shared != 0 || rep.Timelines != 0 || rep.AnswerPairs != 0 {
				t.Errorf("one challenge in the scope, and something was compared between two: %+v", rep)
			}
		}},
		{"the end of the window is not in it (half-open)", func(chs map[string]*edition.CrossChallenge) {
			f := &chs[cxA].Template[0]
			f.Data = append(slices.Clone(f.Data), []byte("2001-01-01T00:10:00Z node-a drained\n")...)
		}, nil},
		{"a time that is not a timestamp word is not a literal time", func(chs map[string]*edition.CrossChallenge) {
			f := &chs[cxB].Template[0]
			f.Data = append(slices.Clone(f.Data), []byte("at=2001-01-01 00:05:00 (local)\n")...)
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chs := cxFix()
			c.edit(chs)
			rep, err := edition.CheckCrossChallenge(chs)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if c.check != nil {
				c.check(t, rep)
			}
		})
	}
	// No challenge at all is not a pass.
	if _, err := edition.CheckCrossChallenge(map[string]*edition.CrossChallenge{}); err == nil {
		t.Error("an empty scope was accepted: B13 to B16 compared nothing")
	}
}
