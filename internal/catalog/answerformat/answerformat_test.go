package answerformat_test

import (
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
)

func ip(i int) *int { return &i }

func i64p(i int64) *int64 { return &i }

// opts returns n distinct valid option ids (oa, ob, ..., then oax, obx, ...).
func opts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "o" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
	}
	return out
}

var (
	pHex12   = answerformat.Params{Length: ip(12)}
	pWindow  = answerformat.Params{WindowSeconds: i64p(3600)}
	pChoices = answerformat.Params{Choices: []string{"a", "b", "c"}}
	pSeq     = answerformat.Params{Labels: []string{"a", "b", "c"}, Length: ip(2)}
)

func TestFormats_AreTheClosedSevenSorted(t *testing.T) {
	want := []string{"choice-set", "hexid", "name", "path", "sequence", "technique", "timestamp"}
	if got := answerformat.Formats(); !slices.Equal(got, want) {
		t.Fatalf("Formats() = %v, want %v (adding a format is an ADR-0056 D2 amendment)", got, want)
	}
	for _, f := range want {
		if !answerformat.Known(f) {
			t.Errorf("Known(%q) = false", f)
		}
	}
	if answerformat.Known("regex") || answerformat.Known("") {
		t.Error("Known accepted a format outside the closed list")
	}
}

func TestPerSeat(t *testing.T) {
	for f, want := range map[string]bool{
		"path": true, "name": true, "hexid": true, "timestamp": true,
		"technique": false, "choice-set": false, "sequence": false,
		"nonsense": false,
	} {
		if got := answerformat.PerSeat(f); got != want {
			t.Errorf("PerSeat(%q) = %v, want %v", f, got, want)
		}
	}
}

var normCases = []struct {
	name   string
	format string
	params answerformat.Params
	in     string
	want   string // "" with bad = true means the input must be refused
	bad    bool
}{
	{"path trims, collapses slashes, drops the trailing slash", "path", answerformat.Params{}, "  /var//log/auth.log/ \n", "/var/log/auth.log", false},
	{"path keeps case", "path", answerformat.Params{}, "/Tmp/Evil", "/Tmp/Evil", false},
	{"path root stays root", "path", answerformat.Params{}, " // ", "/", false},
	{"path must be absolute", "path", answerformat.Params{}, "tmp/x", "", true},
	{"path element outside the set", "path", answerformat.Params{}, "/tmp/a b", "", true},
	{"path non-ASCII element", "path", answerformat.Params{}, "/tmp/é", "", true},
	{"path 255 bytes is the longest", "path", answerformat.Params{}, "/" + strings.Repeat("a", 254), "/" + strings.Repeat("a", 254), false},
	{"path 256 bytes is too long", "path", answerformat.Params{}, "/" + strings.Repeat("a", 255), "", true},

	{"name trims and keeps case", "name", answerformat.Params{}, "  Evil.EXE ", "Evil.EXE", false},
	{"name with a space inside", "name", answerformat.Params{}, "evil exe", "", true},
	{"name empty", "name", answerformat.Params{}, "   ", "", true},
	{"name 64 is the longest", "name", answerformat.Params{}, strings.Repeat("a", 64), strings.Repeat("a", 64), false},
	{"name 65 is too long", "name", answerformat.Params{}, strings.Repeat("a", 65), "", true},

	{"hexid lower-cases", "hexid", pHex12, " 0123456789AB ", "0123456789ab", false},
	{"hexid wrong length", "hexid", pHex12, "0123456789a", "", true},
	{"hexid non-hex digit", "hexid", pHex12, "0123456789ag", "", true},

	{"timestamp already canonical", "timestamp", pWindow, "2026-11-16T10:00:00Z", "2026-11-16T10:00:00Z", false},
	{"timestamp +00:00 becomes Z", "timestamp", pWindow, " 2026-11-16T10:00:00+00:00 ", "2026-11-16T10:00:00Z", false},
	{"timestamp sub-second refused", "timestamp", pWindow, "2026-11-16T10:00:00.5Z", "", true},
	{"timestamp other offset refused", "timestamp", pWindow, "2026-11-16T10:00:00+09:00", "", true},
	{"timestamp impossible month refused", "timestamp", pWindow, "2026-13-16T10:00:00Z", "", true},
	{"timestamp space instead of T refused", "timestamp", pWindow, "2026-11-16 10:00:00Z", "", true},

	{"technique upper-cases", "technique", answerformat.Params{}, " t1059.004 ", "T1059.004", false},
	{"technique without sub-technique", "technique", answerformat.Params{}, "T1059", "T1059", false},
	{"technique short sub-technique", "technique", answerformat.Params{}, "T1059.04", "", true},
	{"technique too few digits", "technique", answerformat.Params{}, "T105", "", true},

	{"choice-set sorts, dedupes and drops whitespace", "choice-set", pChoices, "c, a ,a", "a,c", false},
	{"choice-set empty", "choice-set", pChoices, "  ", "", true},
	{"choice-set empty element", "choice-set", pChoices, "a,,b", "", true},
	{"choice-set undeclared option", "choice-set", pChoices, "a,d", "", true},

	{"sequence trims the ends", "sequence", pSeq, " b,a ", "b,a", false},
	{"sequence is not re-spaced", "sequence", pSeq, "b, a", "", true},
	{"sequence repeats a label", "sequence", pSeq, "a,a", "", true},
	{"sequence too short", "sequence", pSeq, "a", "", true},
	{"sequence too long", "sequence", pSeq, "a,b,c", "", true},
	{"sequence undeclared label", "sequence", pSeq, "a,z", "", true},
}

func TestNormalize_Table(t *testing.T) {
	for _, c := range normCases {
		t.Run(c.name, func(t *testing.T) {
			got, err := answerformat.Normalize(c.format, c.params, c.in)
			if c.bad {
				if !errors.Is(err, answerformat.ErrFormat) {
					t.Fatalf("Normalize(%q, %q) err = %v, want ErrFormat", c.format, c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q, %q): %v", c.format, c.in, err)
			}
			if got != c.want {
				t.Fatalf("Normalize(%q, %q) = %q, want %q", c.format, c.in, got, c.want)
			}
		})
	}
}

// ADR-0056 D2: normalisation is idempotent, and a normalised value is canonical.
func TestNormalize_IsIdempotent(t *testing.T) {
	n := 0
	for _, c := range normCases {
		if c.bad {
			continue
		}
		n++
		once, err := answerformat.Normalize(c.format, c.params, c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		twice, err := answerformat.Normalize(c.format, c.params, once)
		if err != nil || twice != once {
			t.Errorf("%s: Normalize is not idempotent: %q -> %q (err %v)", c.name, once, twice, err)
		}
		if err := answerformat.Canonical(c.format, c.params, once); err != nil {
			t.Errorf("%s: a normalised value is not Canonical: %v", c.name, err)
		}
	}
	if n < 10 {
		t.Fatalf("only %d accepting cases: the idempotence check is hollow", n)
	}
}

func TestCanonical_RefusesAValueThatNormalisesToSomethingElse(t *testing.T) {
	for _, c := range []struct {
		format string
		params answerformat.Params
		v      string
	}{
		{"hexid", pHex12, "0123456789AB"},
		{"path", answerformat.Params{}, "/a//b"},
		{"choice-set", pChoices, "c,a"},
		{"technique", answerformat.Params{}, "t1059"},
		{"timestamp", pWindow, "2026-11-16T10:00:00+00:00"},
	} {
		if err := answerformat.Canonical(c.format, c.params, c.v); !errors.Is(err, answerformat.ErrNotCanonical) {
			t.Errorf("Canonical(%s, %q) err = %v, want ErrNotCanonical", c.format, c.v, err)
		}
	}
	if err := answerformat.Canonical("hexid", pHex12, "xyz"); !errors.Is(err, answerformat.ErrFormat) {
		t.Errorf("Canonical of a malformed value: err = %v, want ErrFormat", err)
	}
}

// ADR-0056 D4/D13: an error must not echo the input.
func TestNormalize_ErrorsNeverEchoTheInput(t *testing.T) {
	const sentinel = "SENTINEL 9f3" // the space makes every format refuse it
	for _, c := range normCases {
		if !c.bad {
			continue
		}
		_, err := answerformat.Normalize(c.format, c.params, sentinel+c.in)
		if err == nil {
			continue // the sentinel happened to be valid for this case; the other cases cover it
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Errorf("%s: error echoes the input: %v", c.name, err)
		}
	}
	// every format at least once, with an input that is certainly refused
	for _, f := range answerformat.Formats() {
		p := map[string]answerformat.Params{"hexid": pHex12, "timestamp": pWindow, "choice-set": pChoices, "sequence": pSeq}[f]
		_, err := answerformat.Normalize(f, p, sentinel)
		if err == nil {
			t.Errorf("format %s accepted %q", f, sentinel)
		} else if strings.Contains(err.Error(), sentinel) {
			t.Errorf("format %s: error echoes the input: %v", f, err)
		}
	}
}

func TestNormalize_AnswerLongerThanTheRequestLimit(t *testing.T) {
	long := strings.Repeat("a", answerformat.MaxAnswerLen+1)
	if _, err := answerformat.Normalize("name", answerformat.Params{}, long); !errors.Is(err, answerformat.ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// Unvalidated params must be an error, never a nil dereference.
func TestNormalizeAndSpace_RefuseUnvalidatedParams(t *testing.T) {
	if _, err := answerformat.Normalize("hexid", answerformat.Params{}, "0123456789ab"); err == nil {
		t.Error("Normalize(hexid) with no params succeeded")
	}
	if _, err := answerformat.Space("sequence", answerformat.Params{}); err == nil {
		t.Error("Space(sequence) with no params succeeded")
	}
	if _, err := answerformat.Normalize("regex", answerformat.Params{}, "x"); err == nil {
		t.Error("Normalize of an unknown format succeeded")
	}
}

func TestValidateParams(t *testing.T) {
	bad := []struct {
		name   string
		format string
		params answerformat.Params
	}{
		{"unknown format", "regex", answerformat.Params{}},
		{"path takes no params", "path", answerformat.Params{Length: ip(3)}},
		{"name takes no params", "name", answerformat.Params{Choices: []string{"a"}}},
		{"technique takes no params", "technique", answerformat.Params{WindowSeconds: i64p(5)}},
		{"hexid needs length", "hexid", answerformat.Params{}},
		{"hexid length below 12", "hexid", answerformat.Params{Length: ip(11)}},
		{"hexid length above 64", "hexid", answerformat.Params{Length: ip(65)}},
		{"hexid takes no windowSeconds", "hexid", answerformat.Params{Length: ip(12), WindowSeconds: i64p(5)}},
		{"timestamp needs windowSeconds", "timestamp", answerformat.Params{}},
		{"timestamp windowSeconds 0", "timestamp", answerformat.Params{WindowSeconds: i64p(0)}},
		{"timestamp takes no length", "timestamp", answerformat.Params{WindowSeconds: i64p(5), Length: ip(12)}},
		{"choice-set needs choices", "choice-set", answerformat.Params{}},
		{"choice-set empty list", "choice-set", answerformat.Params{Choices: []string{}}},
		{"choice-set duplicate", "choice-set", answerformat.Params{Choices: []string{"a", "a"}}},
		{"choice-set id outside the grammar", "choice-set", answerformat.Params{Choices: []string{"A"}}},
		{"choice-set too many", "choice-set", answerformat.Params{Choices: opts(answerformat.MaxLabels + 1)}},
		{"choice-set takes no length", "choice-set", answerformat.Params{Choices: []string{"a"}, Length: ip(1)}},
		{"sequence needs labels", "sequence", answerformat.Params{Length: ip(1)}},
		{"sequence needs length", "sequence", answerformat.Params{Labels: []string{"a", "b"}}},
		{"sequence length above labels", "sequence", answerformat.Params{Labels: []string{"a", "b"}, Length: ip(3)}},
		{"sequence length 0", "sequence", answerformat.Params{Labels: []string{"a", "b"}, Length: ip(0)}},
		{"sequence takes no choices", "sequence", answerformat.Params{Labels: []string{"a"}, Length: ip(1), Choices: []string{"a"}}},
	}
	for _, c := range bad {
		if err := answerformat.ValidateParams(c.format, c.params); err == nil {
			t.Errorf("%s: ValidateParams accepted it", c.name)
		}
	}
	good := []struct {
		format string
		params answerformat.Params
	}{
		{"path", answerformat.Params{}},
		{"name", answerformat.Params{}},
		{"technique", answerformat.Params{}},
		{"hexid", answerformat.Params{Length: ip(12)}},
		{"hexid", answerformat.Params{Length: ip(64)}},
		{"timestamp", pWindow},
		{"choice-set", answerformat.Params{Choices: opts(answerformat.MaxLabels)}},
		{"sequence", pSeq},
	}
	for _, c := range good {
		if err := answerformat.ValidateParams(c.format, c.params); err != nil {
			t.Errorf("ValidateParams(%s) refused a good block: %v", c.format, err)
		}
	}
}

func TestSpace_Values(t *testing.T) {
	cases := []struct {
		name   string
		format string
		params answerformat.Params
		want   string
	}{
		{"hexid 12 digits = 16^12", "hexid", pHex12, "281474976710656"},
		{"timestamp = window", "timestamp", pWindow, "3600"},
		{"choice-set of 4 = 2^4-1", "choice-set", answerformat.Params{Choices: opts(4)}, "15"},
		{"choice-set of 10 = 2^10-1", "choice-set", answerformat.Params{Choices: opts(10)}, "1023"},
		{"sequence 6P3", "sequence", answerformat.Params{Labels: opts(6), Length: ip(3)}, "120"},
		{"sequence 3P2", "sequence", pSeq, "6"},
	}
	for _, c := range cases {
		got, err := answerformat.Space(c.format, c.params)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.String() != c.want {
			t.Errorf("%s: Space = %s, want %s", c.name, got, c.want)
		}
	}
	if _, err := answerformat.Space("path", answerformat.Params{}); !errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
		t.Errorf("Space(path) err = %v, want ErrSpaceFromVocabulary", err)
	}
	if _, err := answerformat.Space("name", answerformat.Params{}); !errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
		t.Errorf("Space(name) err = %v, want ErrSpaceFromVocabulary", err)
	}
	if _, err := answerformat.Space("technique", answerformat.Params{}); !errors.Is(err, answerformat.ErrSpaceUnavailable) {
		t.Errorf("Space(technique) err = %v, want ErrSpaceUnavailable", err)
	}
}

// ADR-0056 D3 (a) / V6: space >= 100 x attempts, at the boundary on both sides.
func TestCheckSpace_Boundaries(t *testing.T) {
	cases := []struct {
		name     string
		format   string
		params   answerformat.Params
		attempts int
		wantErr  bool
	}{
		{"4-option choice-set is refused at 1 attempt (15 < 100)", "choice-set", answerformat.Params{Choices: opts(4)}, 1, true},
		{"4-option choice-set is refused at 10 attempts", "choice-set", answerformat.Params{Choices: opts(4)}, 10, true},
		{"10-option choice-set passes at 10 attempts (1023 >= 1000)", "choice-set", answerformat.Params{Choices: opts(10)}, 10, false},
		{"9-option choice-set passes at 5 attempts (511 >= 500)", "choice-set", answerformat.Params{Choices: opts(9)}, 5, false},
		{"9-option choice-set is refused at 6 attempts (511 < 600)", "choice-set", answerformat.Params{Choices: opts(9)}, 6, true},
		{"timestamp window 500 passes at 5 attempts", "timestamp", answerformat.Params{WindowSeconds: i64p(500)}, 5, false},
		{"timestamp window 499 is refused at 5 attempts", "timestamp", answerformat.Params{WindowSeconds: i64p(499)}, 5, true},
		{"6P3 = 120 passes at 1 attempt", "sequence", answerformat.Params{Labels: opts(6), Length: ip(3)}, 1, false},
		{"6P3 = 120 is refused at 2 attempts", "sequence", answerformat.Params{Labels: opts(6), Length: ip(3)}, 2, true},
		{"hexid 12 passes at 10 attempts", "hexid", pHex12, 10, false},
		{"technique cannot be sized: refused", "technique", answerformat.Params{}, 1, true},
	}
	for _, c := range cases {
		err := answerformat.CheckSpace(c.format, c.params, c.attempts)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: CheckSpace err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

// A vocabulary-sized format is never a silent nil: CheckSpace says so, and the
// caller (the catalog) chooses to pass it (ADR-0056 D3 (a); the edition validator
// sizes it).
func TestCheckSpace_VocabularyFormatsReportItExplicitly(t *testing.T) {
	for _, f := range []string{"path", "name"} {
		if err := answerformat.CheckSpace(f, answerformat.Params{}, 10); !errors.Is(err, answerformat.ErrSpaceFromVocabulary) {
			t.Errorf("CheckSpace(%s) err = %v, want ErrSpaceFromVocabulary", f, err)
		}
	}
	if err := answerformat.CheckSpace("technique", answerformat.Params{}, 1); !errors.Is(err, answerformat.ErrSpaceUnavailable) {
		t.Errorf("CheckSpace(technique) err = %v, want ErrSpaceUnavailable", err)
	}
}

func TestCheckSpaceN(t *testing.T) {
	if err := answerformat.CheckSpaceN(big.NewInt(500), 5); err != nil {
		t.Errorf("500 at 5 attempts: %v", err)
	}
	if err := answerformat.CheckSpaceN(big.NewInt(499), 5); err == nil {
		t.Error("499 at 5 attempts was accepted")
	}
}

// Fail-closed: an attempts that is not 1..MaxAttempts, and an n that is nil or
// not positive, are refused (attempts 0 would make the floor 0 and pass anything).
func TestCheckSpaceN_RefusesOutOfRangeInputs(t *testing.T) {
	big1000 := big.NewInt(1000)
	for _, attempts := range []int{0, -1, answerformat.MaxAttempts + 1} {
		if err := answerformat.CheckSpaceN(big1000, attempts); err == nil {
			t.Errorf("CheckSpaceN(1000, %d) was accepted", attempts)
		}
		// CheckSpace refuses it for every format, a vocabulary-sized one included.
		for _, f := range []string{"path", "hexid"} {
			if err := answerformat.CheckSpace(f, map[string]answerformat.Params{"path": {}, "hexid": pHex12}[f], attempts); err == nil {
				t.Errorf("CheckSpace(%s, attempts %d) was accepted", f, attempts)
			}
		}
	}
	for name, n := range map[string]*big.Int{"nil": nil, "zero": big.NewInt(0), "negative": big.NewInt(-5)} {
		if err := answerformat.CheckSpaceN(n, 1); err == nil {
			t.Errorf("CheckSpaceN(%s, 1) was accepted", name)
		}
	}
	if err := answerformat.CheckSpaceN(big1000, answerformat.MaxAttempts); err != nil {
		t.Errorf("the upper bound itself must pass: %v", err)
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{
		"a": true, "first-tool": true, "q1": true, strings.Repeat("a", 31): true,
		"": false, "1a": false, "A": false, "a_b": false, strings.Repeat("a", 32): false, "a b": false,
	} {
		if got := answerformat.ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}
