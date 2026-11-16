package edition_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

func newJudge(t *testing.T, rows [][]string, run string) *edition.Judge {
	t.Helper()
	j, err := edition.NewJudge(mustParse(t, render(run, rows)))
	if err != nil {
		t.Fatalf("NewJudge: %v", err)
	}
	return j
}

func TestJudge_Match(t *testing.T) {
	j := newJudge(t, baseRows(), runA)
	cases := []struct {
		name      string
		seat, cid string
		qid       string
		input     string
		ok, known bool
	}{
		{"own value", "seat-a", demoCID, "who", sentinel + "-a", true, true},
		{"own hexid", "seat-b", demoCID, "hx", "bbbbbbbbbbbb", true, true},
		{"shared choice-set", "seat-b", demoCID, "pick", "ca,cb", true, true},
		{"wrong value", "seat-a", demoCID, "who", sentinel + "-zz", false, true},
		{"another seat's value", "seat-a", demoCID, "who", sentinel + "-b", false, true},
		{"empty input", "seat-a", demoCID, "who", "", false, true},
		{"a seat the table does not name", "seat-c", demoCID, "who", sentinel + "-a", false, false},
		{"an unknown qid", "seat-a", demoCID, "nope", "x", false, false},
		{"an unknown cid", "seat-a", "02-other", "who", "x", false, false},
	}
	for _, c := range cases {
		ok, known := j.Match(c.seat, c.cid, c.qid, c.input)
		if ok != c.ok || known != c.known {
			t.Errorf("%s: Match = (%v, %v), want (%v, %v)", c.name, ok, known, c.ok, c.known)
		}
	}
}

// A practice table's seat * answers for every seat (D8, D12).
func TestJudge_PracticeSeatAnswersForAnySeat(t *testing.T) {
	rows := [][]string{{"*", demoCID, "who", "practice-name"}}
	j := newJudge(t, rows, edition.PracticeRunID)
	for _, seat := range []string{"seat-a", "user7"} {
		if ok, known := j.Match(seat, demoCID, "who", "practice-name"); !ok || !known {
			t.Errorf("seat %s: Match = (%v, %v), want (true, true)", seat, ok, known)
		}
		if ok, known := j.Match(seat, demoCID, "who", "other"); ok || !known {
			t.Errorf("seat %s, wrong value: Match = (%v, %v), want (false, true)", seat, ok, known)
		}
	}
	if seat, found := j.OtherSeat("seat-a", demoCID, "who", "practice-name"); found {
		t.Errorf("OtherSeat named %q: the practice seat * is not a seat", seat)
	}
}

func TestJudge_OtherSeat(t *testing.T) {
	j := newJudge(t, baseRows(), runA)
	cases := []struct {
		name      string
		own       string
		qid       string
		input     string
		wantSeat  string
		wantFound bool
	}{
		{"seat-a typed seat-b's name", "seat-a", "who", sentinel + "-b", "seat-b", true},
		{"seat-b typed seat-a's hexid", "seat-b", "hx", "aaaaaaaaaaaa", "seat-a", true},
		{"own value is not another seat", "seat-a", "who", sentinel + "-a", "", false},
		{"nobody's value", "seat-a", "who", sentinel + "-zz", "", false},
		{"a value another question holds", "seat-a", "who", "bbbbbbbbbbbb", "", false},
		{"unknown question", "seat-a", "nope", sentinel + "-b", "", false},
	}
	for _, c := range cases {
		seat, found := j.OtherSeat(c.own, demoCID, c.qid, c.input)
		if seat != c.wantSeat || found != c.wantFound {
			t.Errorf("%s: OtherSeat = (%q, %v), want (%q, %v)", c.name, seat, found, c.wantSeat, c.wantFound)
		}
	}
}

func TestNewJudge_RefusesAnEmptyOrMissingTable(t *testing.T) {
	if _, err := edition.NewJudge(nil); err == nil {
		t.Error("NewJudge(nil) succeeded")
	}
	if _, err := edition.NewJudge(mustParse(t, render(runA, nil))); err == nil {
		t.Error("NewJudge of a table with no row succeeded")
	}
}

// The key is per process: two judges of one table are two keys. Their MACs are not
// observable, so the check is that both still judge correctly and are distinct
// objects.
func TestNewJudge_EachCallIsItsOwnJudge(t *testing.T) {
	a := newJudge(t, baseRows(), runA)
	b := newJudge(t, baseRows(), runA)
	if a == b {
		t.Fatal("two NewJudge calls returned one Judge")
	}
	for _, j := range []*edition.Judge{a, b} {
		if ok, _ := j.Match("seat-a", demoCID, "who", sentinel+"-a"); !ok {
			t.Error("a judge does not match its own table")
		}
	}
}

// ADR-0056 D13 / V1: a Judge prints as a fixed string under every verb, as a value
// and as a pointer, and under encoding/json.
func TestJudge_PrintsNoValue(t *testing.T) {
	j := newJudge(t, baseRows(), runA)
	texts := []string{
		fmt.Sprintf("%v", j), fmt.Sprintf("%+v", j), fmt.Sprintf("%#v", j), fmt.Sprintf("%s", j), fmt.Sprintf("%x", j), fmt.Sprintf("%d", j),
		fmt.Sprintf("%v", *j), fmt.Sprintf("%+v", *j), fmt.Sprintf("%#v", *j),
		j.String(), j.GoString(),
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, string(b))
	noSecretIn(t, "Judge", texts...)
	for _, s := range texts {
		if s != "edition.Judge{redacted}" && s != `"edition.Judge{redacted}"` {
			t.Errorf("Judge printed %q, want the fixed redacted string", s)
		}
	}
}

// No method of a Judge returns a plaintext (or a MAC): the whole exported surface
// is pinned. Adding a method is a decision for this list, and for a reviewer.
func TestJudge_ExportedSurfaceIsPinned(t *testing.T) {
	want := []string{"Format", "GoString", "MarshalJSON", "Match", "OtherSeat", "String"}
	typ := reflect.TypeOf(&edition.Judge{})
	var got []string
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Judge methods = %v, want %v", got, want)
	}
}

// A Judge is read-only after NewJudge: concurrent use under -race.
func TestJudge_ConcurrentUse(t *testing.T) {
	j := newJudge(t, baseRows(), runA)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if ok, known := j.Match("seat-a", demoCID, "who", sentinel+"-a"); !ok || !known {
					t.Errorf("Match = (%v, %v)", ok, known)
					return
				}
				if seat, found := j.OtherSeat("seat-a", demoCID, "who", sentinel+"-b"); !found || seat != "seat-b" {
					t.Errorf("OtherSeat = (%q, %v)", seat, found)
					return
				}
			}
		}()
	}
	wg.Wait()
}
