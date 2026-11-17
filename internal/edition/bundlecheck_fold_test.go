package edition_test

// ADR-0056 V55 (A4c-2, M4), the B9 half: the corpus is folded per format
// (answerformat.Fold), so a per-seat answer that is in a public file in a spelling that
// grading accepts is found, and a byte comparison of the normalised value alone would
// have let it through. The case table is one corpus per spelling; every value is a
// placeholder. fold_test.go (internal/catalog/answerformat) holds the property of Fold
// itself.

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
	"github.com/Qfour/falco-ctf-app/internal/hintleak"
)

const (
	foldPathA = "/srv/data/alpha.log"
	foldTimeA = "2026-01-02T03:04:05Z"
	foldHexA  = "abcdef012345"
	foldNameA = "Alpha-One"
)

// foldScope has one question of each per-seat format.
func foldScope() edition.Scope {
	w := int64(3600)
	return edition.Scope{
		demoCID: {
			{ID: "pa", Format: answerformat.Path, Attempts: 5},
			{ID: "ts", Format: answerformat.Timestamp, Params: answerformat.Params{WindowSeconds: &w}, Attempts: 5},
			{ID: "hx", Format: answerformat.HexID, Params: answerformat.Params{Length: ip(12)}, Attempts: 5},
			{ID: "nm", Format: answerformat.Name, Attempts: 5},
		},
	}
}

func foldRows() [][]string {
	return [][]string{
		{"seat-a", demoCID, "pa", foldPathA},
		{"seat-a", demoCID, "ts", foldTimeA},
		{"seat-a", demoCID, "hx", foldHexA},
		{"seat-a", demoCID, "nm", foldNameA},
		{"seat-b", demoCID, "pa", "/srv/data/beta.log"},
		{"seat-b", demoCID, "ts", "2026-01-02T03:04:06Z"},
		{"seat-b", demoCID, "hx", "abcdef012346"},
		{"seat-b", demoCID, "nm", "Beta-Two"},
	}
}

// foldBundles: each seat's bundle holds its four answers.
func foldBundles() map[string]string {
	return kv(
		notesA, "path "+foldPathA+"\ntime "+foldTimeA+"\nid "+foldHexA+"\nname "+foldNameA+"\n",
		notesB, "path /srv/data/beta.log\ntime 2026-01-02T03:04:06Z\nid abcdef012346\nname Beta-Two\n",
	)
}

// foldTable is the answers table that foldInput's bundles are held to.
func foldTable(t *testing.T) *edition.CheckedTable {
	t.Helper()
	return mustChecked(t, render(runA, foldRows()))
}

func foldInput(t *testing.T, corpus edition.Corpus) edition.BundleInput {
	t.Helper()
	return edition.BundleInput{
		Scope:      foldScope(),
		Seats:      []string{"seat-a", "seat-b"},
		FlagValues: []string{eventFlg},
		Hints:      []hintleak.Item{{Source: "01-demo hints[0]", Text: hintText}},
		Free:       []hintleak.Item{{Source: "01-demo briefing", Text: "plain words only"}},
		Corpus:     corpus,
	}
}

// The corpus holds a spelling that grading accepts and a byte comparison of the
// normalised value does not find: B9 refuses it (and names the question). The last case
// is the control: the answer as it is, which a byte comparison found before.
func TestCheckBundles_B9FindsEveryAcceptedSpellingInTheCorpus(t *testing.T) {
	cases := []struct {
		name         string
		corpus       edition.Corpus
		value        string // the normalised answer the corpus holds
		qid          string
		byteComparer bool // a byte comparison of value would find it too
	}{
		{"a path with doubled slashes", edition.Corpus{[]byte("see //srv///data/alpha.log here")}, foldPathA, "pa", false},
		{"a path with a trailing slash and doubled ones inside", edition.Corpus{[]byte("/srv//data/alpha.log//")}, foldPathA, "pa", false},
		{"a timestamp with +00:00", edition.Corpus{[]byte("at 2026-01-02T03:04:05+00:00 in a log")}, foldTimeA, "ts", false},
		{"a hexid in capitals", edition.Corpus{[]byte("id ABCDEF012345")}, foldHexA, "hx", false},
		{"a hexid in mixed case", edition.Corpus{[]byte("id AbCdEf012345")}, foldHexA, "hx", false},
		{"a hexid in capitals in a binary file", edition.Corpus{[]byte("\xff\xfe ABCDEF012345 \x00")}, foldHexA, "hx", false},
		{"the spelling is in the second file", edition.Corpus{[]byte("nothing"), []byte("x ABCDEF012345 y")}, foldHexA, "hx", false},
		{"a name as it is (the control)", edition.Corpus{[]byte("name Alpha-One")}, foldNameA, "nm", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plain := false
			for _, data := range c.corpus {
				plain = plain || bytes.Contains(data, []byte(c.value))
			}
			if plain != c.byteComparer {
				t.Fatalf("a byte comparison finds %q in the corpus: %v, the case says %v: the case does not tell a fold from a byte comparison", c.value, plain, c.byteComparer)
			}
			cb, err := edition.CheckBundles(bundleTree(t, foldBundles()), foldTable(t), foldInput(t, c.corpus))
			if err == nil {
				t.Fatal("B9 did not refuse a per-seat answer that is in the corpus")
			}
			if cb != nil {
				t.Errorf("digest rows were returned with a violation: %v", cb.Rows())
			}
			if got := rules(err); !slices.Equal(got, []string{edition.RuleBundleCorpus}) {
				t.Errorf("rules = %v, want only [B9]: %v", got, err)
			}
			named := false
			for _, line := range strings.Split(err.Error(), "\n") {
				if strings.HasPrefix(line, "B9: ") && strings.Contains(line, "seat=seat-a cid="+demoCID+" qid="+c.qid) {
					named = true
				}
			}
			if !named {
				t.Errorf("no B9 violation names seat-a, %s, %s: %v", demoCID, c.qid, err)
			}
			for _, bad := range []string{c.value, "ABCDEF012345", "+00:00", "//srv"} {
				if strings.Contains(err.Error(), bad) {
					t.Errorf("the error carries %q: %v", bad, err)
				}
			}
		})
	}
}

// What the fold must not find: near misses, the case of a name (a name is case
// sensitive), another offset, and a text that is not a spelling of the answer.
func TestCheckBundles_B9AcceptsACorpusWithoutAnySpellingOfAnAnswer(t *testing.T) {
	cases := []struct {
		name   string
		corpus edition.Corpus
	}{
		{"unrelated text", edition.Corpus{[]byte("nothing that is an answer")}},
		{"a path that is one element short", edition.Corpus{[]byte("//srv///data/alpha.lo")}},
		{"another second", edition.Corpus{[]byte("2026-01-02T03:04:07+00:00")}},
		{"another offset", edition.Corpus{[]byte("2026-01-02T03:04:05+01:00")}},
		{"a hexid that differs in its last digit", edition.Corpus{[]byte("ABCDEF012347")}},
		{"a name in another case", edition.Corpus{[]byte("name alpha-one ALPHA-ONE")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := edition.CheckBundles(bundleTree(t, foldBundles()), foldTable(t), foldInput(t, c.corpus)); err != nil {
				t.Errorf("B9 refused a corpus that holds no spelling of an answer: %v", err)
			}
		})
	}
}

// The same text can be one format's answer and another's: a hit is of the answer's own
// format. A NAME answer with the letters of a hexid is not found in a corpus that holds
// them in capitals (a name's fold is the identity), so the fold of one format does not
// leak into another's search; it is found as it is.
func TestCheckBundles_B9FoldsPerFormat(t *testing.T) {
	rows := [][]string{
		{"seat-a", demoCID, "nm", "abcdef012345"},
		{"seat-b", demoCID, "nm", "abcdef012346"},
	}
	files := kv(notesA, "name abcdef012345\n", notesB, "name abcdef012346\n")
	table := mustChecked(t, render(runA, rows))
	in := edition.BundleInput{
		Scope:      edition.Scope{demoCID: {{ID: "nm", Format: answerformat.Name, Attempts: 5}}},
		Seats:      []string{"seat-a", "seat-b"},
		FlagValues: []string{eventFlg},
		Hints:      []hintleak.Item{{Source: "01-demo hints[0]", Text: hintText}},
		Free:       []hintleak.Item{{Source: "01-demo briefing", Text: "plain words only"}},
		Corpus:     edition.Corpus{[]byte("ABCDEF012345 and ABCDEF012346")},
	}
	if _, err := edition.CheckBundles(bundleTree(t, files), table, in); err != nil {
		t.Errorf("a name answer was found in a corpus that holds its capitals (a name is not folded): %v", err)
	}
	in.Corpus = edition.Corpus{[]byte("name abcdef012345")}
	if _, err := edition.CheckBundles(bundleTree(t, files), table, in); err == nil {
		t.Error("a name answer that is in the corpus as it is was not found")
	}
}
