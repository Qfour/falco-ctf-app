package specparity

// ADR-0039 S1 (D3): every string Schema Object of every spec declares who can
// choose its bytes with `x-ctf-text-origin`. The walker and the vocabulary
// live in textorigin.go (test-only, so no cmd/* binary builds them); this file
// runs them against the real docs/openapi-*.yaml and pins the per-word counts.
// It sits in this package rather than internal/apispec because internal/apispec's
// own (internal) tests cannot import specparity: specparity imports apispec.
//
// Why the counts are pinned: a PR that adds a string node must classify it
// (a missing key fails), and the pin below must then move in the same PR, so
// the reviewer sees the word that was chosen in the diff of THIS file as well
// as the spec (ADR-0009's count-pin shape). A PR that re-labels a node (say
// `operator` -> `token`) moves two numbers; one that is only a typo in a word
// fails the vocabulary check. There is no exclusion list and no default.

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// textOriginPin is one spec's expected string-node count and its split by
// word. total is ADR-0039 C3's per-spec count (scoreboard 159 / collector 4 /
// auth-policy 18 = 181). byWord must name every word of the vocabulary.
type textOriginPin struct {
	total  int
	byWord map[string]int
}

// textOriginPins is keyed by the spec file name. The files checked are every
// docs/openapi-*.yaml (a glob, not a list), and the pins must name exactly
// those files, so a spec added without its pin fails here and
// internal/apispec's TestSpecExistsForEveryMuxOwningBinary (ADR-0005 V6)
// separately keeps "every mux-owning binary has a spec" complete.
var textOriginPins = map[string]textOriginPin{
	"openapi-scoreboard.yaml": {total: 159, byWord: map[string]int{
		OriginParticipantInline: 17,
		OriginParticipantBlock:  4,
		OriginParticipantOpaque: 19,
		OriginOperator:          47,
		OriginToken:             54,
		OriginEnum:              18,
	}},
	"openapi-collector.yaml": {total: 4, byWord: map[string]int{
		OriginParticipantInline: 0,
		OriginParticipantBlock:  0,
		OriginParticipantOpaque: 1,
		OriginOperator:          1,
		OriginToken:             2,
		OriginEnum:              0,
	}},
	"openapi-auth-policy.yaml": {total: 18, byWord: map[string]int{
		OriginParticipantInline: 0,
		OriginParticipantBlock:  0,
		OriginParticipantOpaque: 6,
		OriginOperator:          2,
		OriginToken:             10,
		OriginEnum:              0,
	}},
}

// TestAPISpec_TextOriginDeclared is ADR-0039 V1 (S1 part): over every
// docs/openapi-*.yaml, (a) every string node has the key, (b) the value is one of
// the six words, the key is on no other node, every $ref resolves and the
// walk misses no string node (all inside TextOrigin()), and (c) the per-word
// counts equal the pin above.
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
				t.Fatalf("docs/%s has no entry in textOriginPins: a new spec must pin its per-word counts here", file)
			}
			if len(pin.byWord) != len(TextOriginVocabulary) {
				t.Fatalf("textOriginPins[%s] names %d words, the vocabulary has %d: pin every word (0 included)", file, len(pin.byWord), len(TextOriginVocabulary))
			}
			sum := 0
			for _, w := range TextOriginVocabulary {
				n, ok := pin.byWord[w]
				if !ok {
					t.Fatalf("textOriginPins[%s] has no count for %q", file, w)
				}
				sum += n
			}
			if sum != pin.total {
				t.Fatalf("textOriginPins[%s]: the per-word counts sum to %d but total is %d (the pin disagrees with itself)", file, sum, pin.total)
			}

			if len(rep.Nodes) != pin.total {
				t.Errorf("docs/%s has %d string nodes, the pin says %d (ADR-0039 C3): classify the new/removed string and move the pin in textOriginPins in the same PR", file, len(rep.Nodes), pin.total)
			}
			for _, w := range TextOriginVocabulary {
				if got, want := rep.Counts[w], pin.byWord[w]; got != want {
					t.Errorf("docs/%s: %d node(s) declare %q, the pin says %d: a node was added, removed or re-labelled; if intended, move textOriginPins and say why in the PR (the reviewer reads this number)", file, got, w, want)
				}
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
	// pins must not name a spec that is no longer there (a stale pin would
	// hide a removed spec).
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
