package specparity

// ADR-0039 S1 (D3): every string Schema Object of every spec declares who can
// choose its bytes with `x-ctf-text-origin`. The walker and the vocabulary
// live in textorigin.go (test-only, so no cmd/* binary builds them); this file
// runs them against the real docs/openapi-*.yaml and pins what a reviewer must
// see. It sits in this package rather than internal/apispec because
// internal/apispec's own (internal) tests cannot import specparity:
// specparity imports apispec.
//
// What is pinned (ADR-0039 D3 (g), narrowed by the VP on review-5x 37):
//
//   - per spec, the JSON pointer of every participant-inline,
//     participant-block and participant-opaque node. These are the words
//     where a wrong answer is a security statement (what a participant can
//     put in front of another person, and what is promised never to be
//     echoed), so adding, removing or re-labelling one moves a line of THIS
//     file and the reviewer sees the pointer, not a count that might balance
//     out (an inline -> opaque swap would not move a count of 17 + 26).
//   - per spec, the total number of string nodes (159 / 4 / 18 = 181). A new
//     string whose declaration is missing fails the check; the total pin then
//     makes adding or dropping a classified string a visible edit too.
//
// operator / token / enum are NOT pinned by count: they churn with ordinary
// work (a new id field, a new enum) without changing who can choose bytes,
// and a count there would turn the pin into noise. They are still required
// on every node and checked against the closed vocabulary.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// textOriginPin is one spec's expectation: its string-node total and, for the
// three participant-* words, the set of JSON pointers.
type textOriginPin struct {
	total       int
	participant map[string][]string // every participant-* word must be a key (empty slice = none)
}

// participantWords is the subset of the vocabulary that is pinned by pointer.
var participantWords = []string{OriginParticipantInline, OriginParticipantBlock, OriginParticipantOpaque}

// textOriginPins is keyed by the spec file name. The files checked are every
// docs/openapi-*.yaml (a glob, not a list), and the pins must name exactly
// those files, so a spec added without its pin fails here;
// internal/apispec's TestSpecFilesAreExactlyTheMuxOwningBinariesSpecs keeps
// the glob equal to specNameForCmd's values, and
// TestSpecExistsForEveryMuxOwningBinary (ADR-0005 V6) keeps "every
// mux-owning binary has a spec" complete.
var textOriginPins = map[string]textOriginPin{
	"openapi-scoreboard.yaml": {total: 150, participant: map[string][]string{
		OriginParticipantInline: {
			"/components/schemas/BoardMessage/properties/authorDisplay",
			"/components/schemas/BoardSummary/properties/authorDisplay",
			"/components/schemas/BoardSummary/properties/subject",
			"/components/schemas/BoardThread/properties/authorDisplay",
			"/components/schemas/BoardThread/properties/subject",
			"/components/schemas/ChallengeSolver/properties/display_name",
			"/components/schemas/CreateThreadRequest/properties/subject",
			"/components/schemas/DisplayNameRequest/properties/name",
			"/components/schemas/DisplayNameResult/properties/display_name",
			"/components/schemas/Journey/properties/display_name",
			"/components/schemas/LeaderboardEntry/properties/display_name",
			"/components/schemas/Me/properties/display_name",
			"/components/schemas/ProfileRequest/properties/display_name",
			"/components/schemas/ProfileResult/properties/display_name",
			"/components/schemas/SolveRecord/properties/display_name",
			"/components/schemas/SubmitDetectVerdict/properties/display_name",
			"/components/schemas/SubmitFlagVerdict/properties/display_name",
		},
		OriginParticipantBlock: {
			"/components/schemas/BoardMessage/properties/body",
			"/components/schemas/CreateThreadRequest/properties/body",
			"/components/schemas/PostMessageRequest/properties/body",
			"/components/schemas/PostReplyRequest/properties/body",
		},
		OriginParticipantOpaque: {
			"/components/schemas/CreateThreadRequest/properties/audience",
			"/components/schemas/ExfilRequest/properties/flag",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/blocked-uri",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/disposition",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/document-uri",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/effective-directive",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/script-sample",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/source-file",
			"/components/schemas/LegacyCSPReport/properties/csp-report/properties/violated-directive",
			"/components/schemas/ReportsAPIEntry/properties/body/properties/blockedURL",
			"/components/schemas/ReportsAPIEntry/properties/body/properties/disposition",
			"/components/schemas/ReportsAPIEntry/properties/body/properties/documentURL",
			"/components/schemas/ReportsAPIEntry/properties/body/properties/effectiveDirective",
			"/components/schemas/ReportsAPIEntry/properties/body/properties/sample",
			"/components/schemas/ReportsAPIEntry/properties/body/properties/sourceFile",
			"/components/schemas/ReportsAPIEntry/properties/type",
			"/components/schemas/SubmitDetectRequest/properties/condition",
			"/components/schemas/SubmitFlagRequest/properties/flag",
			"/paths/~1api~1users~1{user}~1journey/get/parameters/1/schema",
		},
	}},
	"openapi-collector.yaml": {total: 4, participant: map[string][]string{
		OriginParticipantInline: {},
		OriginParticipantBlock:  {},
		OriginParticipantOpaque: {
			"/paths/~1api~1challenges~1{cid}~1exfil/post/requestBody/content/application~1json/schema/properties/flag",
		},
	}},
	"openapi-auth-policy.yaml": {total: 18, participant: map[string][]string{
		OriginParticipantInline: {},
		OriginParticipantBlock:  {},
		OriginParticipantOpaque: {
			"/paths/~1check-admin/get/parameters/0/schema",
			"/paths/~1check-admin/get/parameters/1/schema",
			"/paths/~1check-participant/get/parameters/0/schema",
			"/paths/~1check-participant/get/parameters/1/schema",
			"/paths/~1check-workspace/get/parameters/1/schema",
			"/paths/~1check-workspace/get/parameters/2/schema",
		},
	}},
}

// pointerSetDiff returns (added, removed): pointers in got but not want, and in want but not got.
func pointerSetDiff(got, want []string) (added, removed []string) {
	w := map[string]bool{}
	for _, p := range want {
		w[p] = true
	}
	g := map[string]bool{}
	for _, p := range got {
		g[p] = true
		if !w[p] {
			added = append(added, p)
		}
	}
	for _, p := range want {
		if !g[p] {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// TestPointerSetDiff proves the pin comparison itself goes red on an
// addition, a removal and a swap (a count-based pin would miss the swap).
func TestPointerSetDiff(t *testing.T) {
	cases := []struct {
		name      string
		got, want []string
		added     []string
		removed   []string
	}{
		{"equal", []string{"/a", "/b"}, []string{"/b", "/a"}, nil, nil},
		{"added", []string{"/a", "/b", "/c"}, []string{"/a", "/b"}, []string{"/c"}, nil},
		{"removed", []string{"/a"}, []string{"/a", "/b"}, nil, []string{"/b"}},
		{"swapped keeps the count", []string{"/a", "/c"}, []string{"/a", "/b"}, []string{"/c"}, []string{"/b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			added, removed := pointerSetDiff(tc.got, tc.want)
			if fmt.Sprint(added) != fmt.Sprint(tc.added) || fmt.Sprint(removed) != fmt.Sprint(tc.removed) {
				t.Fatalf("diff(%v, %v) = +%v -%v, want +%v -%v", tc.got, tc.want, added, removed, tc.added, tc.removed)
			}
		})
	}
}

// TestAPISpec_TextOriginDeclared is ADR-0039 V1 (S1 part): over every
// docs/openapi-*.yaml, (a) every string node has the key, (b) the value is one
// of the six words, the key is on no other node, every  is a component
// reference that exists, no mapping has a non-string key and the walk misses
// no string node (all inside TextOrigin()), and (c) the participant-* pointer
// sets and the node total equal the pins above.
func TestAPISpec_TextOriginDeclared(t *testing.T) {
	docs := filepath.Join("..", "..", "..", "docs") // internal/apispec/specparity -> repo root
	paths, err := filepath.Glob(filepath.Join(docs, "openapi-*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		files = append(files, filepath.Base(p))
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatalf("no docs/openapi-*.yaml found under %s: this check would be a silent no-op", docs)
	}

	used := map[string]int{}
	grand := 0
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			spec, err := LoadSpec(filepath.Join(docs, file))
			if err != nil {
				t.Fatalf("load docs/%s: %v", file, err)
			}
			rep := spec.TextOrigin()
			if len(rep.Violations) > 0 {
				t.Fatalf("docs/%s: %d x-ctf-text-origin violation(s) (ADR-0039 D3; no exclusion list: declare the node, do not exempt it):\n  %s",
					file, len(rep.Violations), strings.Join(rep.Violations, "\n  "))
			}

			pin, ok := textOriginPins[file]
			if !ok {
				t.Fatalf("docs/%s has no entry in textOriginPins: a new spec must pin its node total and participant-* pointers here", file)
			}
			for _, w := range participantWords {
				if _, ok := pin.participant[w]; !ok {
					t.Fatalf("textOriginPins[%s] has no entry for %q: list its pointers (an empty list when there are none)", file, w)
				}
			}
			if len(pin.participant) != len(participantWords) {
				t.Fatalf("textOriginPins[%s] names %d words, want exactly the %d participant-* words (operator / token / enum are not pinned by count)", file, len(pin.participant), len(participantWords))
			}

			if len(rep.Nodes) != pin.total {
				t.Errorf("docs/%s has %d string nodes, the pin says %d (ADR-0039 C3): classify the new/removed string and move the total in textOriginPins in the same PR", file, len(rep.Nodes), pin.total)
			}

			got := map[string][]string{}
			for _, n := range rep.Nodes {
				if w, ok := n.Raw.(string); ok {
					got[w] = append(got[w], n.Pointer)
				}
			}
			for _, w := range participantWords {
				added, removed := pointerSetDiff(got[w], pin.participant[w])
				if len(added) > 0 || len(removed) > 0 {
					t.Errorf("docs/%s: the %q set moved (security-engineer review marker). If intended, move textOriginPins in the same PR and say why.\n  now %q but not pinned: %v\n  pinned %q but no longer declared: %v", file, w, w, added, w, removed)
				}
			}
			for _, w := range TextOriginVocabulary {
				used[w] += rep.Counts[w]
			}
			grand += len(rep.Nodes)
		})
	}

	// ADR-0039 D3 (f): a word nobody uses is dead vocabulary.
	for _, w := range TextOriginVocabulary {
		if used[w] == 0 {
			t.Errorf("no string node in any spec declares %q: a word that is never used must not stay in the vocabulary (ADR-0039 D2 / D3 (f))", w)
		}
	}
	// pins must name exactly the specs that are there (a stale pin would hide a
	// removed spec).
	for file := range textOriginPins {
		found := false
		for _, f := range files {
			if f == file {
				found = true
			}
		}
		if !found {
			t.Errorf("textOriginPins has %q, which is not a docs/openapi-*.yaml", file)
		}
	}
	if grand == 0 {
		t.Fatal("0 string nodes checked across all specs: the walk is broken")
	}
}

// TestAPISpec_TextOriginCollectorCopyMatchesTarget is ADR-0039 D3 (e) on the
// real specs: the collector's forwarded exfil body (an inline copy, since a
// spec cannot $ref across documents) accepts exactly what the scoreboard's
// target operation accepts: same words, same acceptance keywords, same
// required. The pairing is the collector operation's x-ctf-forward-target.
func TestAPISpec_TextOriginCollectorCopyMatchesTarget(t *testing.T) {
	docs := filepath.Join("..", "..", "..", "docs")
	collector, err := LoadSpec(filepath.Join(docs, "openapi-collector.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	scoreboard, err := LoadSpec(filepath.Join(docs, "openapi-scoreboard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	v, compared := CollectorCopyViolations(collector, scoreboard)
	if len(v) > 0 {
		t.Fatalf("the collector's request-body copy and its forward target disagree (ADR-0039 D3 (e)):\n  %s", strings.Join(v, "\n  "))
	}
	// exfil's {user, flag}. 0 or fewer would mean the comparison silently
	// found nothing to compare.
	if compared < 2 {
		t.Fatalf("compared %d string nodes, want at least 2 (exfil's user and flag): the check found nothing to compare", compared)
	}
}
