package edition_test

// ADR-0056 V107 to V110 (A7-x PR 3): B13 to B16 on the REAL tree, by the one function `edition
// check` calls (CheckCrossChallenge), given the practice editions the image publishes: each
// challenge's edition.yaml and template/, and its practice/ (the answers of seat * and the bundle
// of seat *). The scopes are every scenario of scenarios/ and the whole catalog; a scope with fewer
// than two investigate challenges has no pair. The scope of scenarios/ir-nimbus-desk must be among
// them and hold 50-nimbus-desk-triage and 51-nimbus-desk-egress (a comparison of nothing is not a
// pass), and every rule must have compared something in it. B14's shingle rule has known violations
// on the real tree (crossKnownB14): its violations must be exactly those.
//
// The copies that must be red (the V's "壊した copy") are made of the inputs of that scope in
// memory: the tree on disk is never written. A copy is red when the rule names a violation that
// the unbroken inputs do not have (so the case says something even when the unbroken inputs are
// refused by the same rule).

import (
	"errors"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
	"github.com/Qfour/falco-ctf-app/internal/catalog/answerformat"
	"github.com/Qfour/falco-ctf-app/internal/edition"
)

const (
	crossScenariosDir = "../../scenarios"
	crossIRScenario   = "ir-nimbus-desk"
	crossIRA          = "50-nimbus-desk-triage"
	crossIRB          = "51-nimbus-desk-egress"
)

// crossRules are the four rules, in order.
var crossRules = []string{edition.RuleCrossAnswer, edition.RuleCrossShare, edition.RuleCrossTimeline, edition.RuleCrossWindow}

// crossPracticeScope is B13 to B16's input for the practice editions of the investigate challenges
// of cat (a scope of the real tree).
func crossPracticeScope(t *testing.T, cat catalog.Catalog) map[string]*edition.CrossChallenge {
	t.Helper()
	out := map[string]*edition.CrossChallenge{}
	for _, id := range cat.IDs() {
		ch := cat[id]
		if ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
			continue
		}
		spec, tmpl := goldenInputs(t, goldenRealDir, ch)
		pf, err := goldenOnDisk(filepath.Join(goldenRealDir, ch.Dir(), goldenEditionDir))
		if err != nil {
			t.Fatalf("%s: the committed practice/ cannot be read: %v", id, err)
		}
		out[id] = &edition.CrossChallenge{
			Questions: ch.Investigate.Questions,
			Evidence:  ch.Investigate.Evidence,
			Spec:      spec,
			Template:  tmpl,
			Bundles:   []*edition.Bundle{{Seat: edition.AnySeat, CID: id, Files: pf.Evidence}},
			Answers:   edition.SeatAnswersOfTableForTest(mustParse(t, pf.Answers), id),
		}
	}
	return out
}

// crossRealScopes is every scope of the real tree, by name: each scenario's challenges
// (catalog.LoadScenario, restricted from the whole catalog) and the whole catalog ("all").
func crossRealScopes(t *testing.T) map[string]catalog.Catalog {
	t.Helper()
	full, err := catalog.Load(goldenRealDir)
	if err != nil {
		t.Fatalf("catalog.Load(%s): %v", goldenRealDir, err)
	}
	out := map[string]catalog.Catalog{"all": full}
	files, err := filepath.Glob(filepath.Join(crossScenariosDir, "*", "scenario.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no scenario under %s (%v): the path is wrong", crossScenariosDir, err)
	}
	for _, f := range files {
		sc, err := catalog.LoadScenario(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		scope := catalog.Catalog{}
		for _, id := range sc.Challenges {
			ch, ok := full[id]
			if !ok {
				t.Fatalf("%s: challenge %s is not in the tree", f, id)
			}
			scope[id] = ch
		}
		out[filepath.Base(filepath.Dir(f))] = scope
	}
	return out
}

// crossViolations is the text of every violation of the rule inside err (an errors.Join), sorted.
// A list that the collector cut (a *MoreViolations in it) fails the test: a rule's violations
// could be among those not listed, and a rule that reads as clean would not be.
func crossViolations(t *testing.T, err error, rule string) []string {
	t.Helper()
	var out []string
	for _, v := range crossViolationList(t, err, rule) {
		out = append(out, v.Error())
	}
	slices.Sort(out)
	return out
}

// crossViolationList is every violation of the rule inside err, in the order listed. A list that
// the collector cut fails the test (crossViolations).
func crossViolationList(t *testing.T, err error, rule string) []*edition.Violation {
	t.Helper()
	var out []*edition.Violation
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range j.Unwrap() {
				walk(x)
			}
			return
		}
		var more *edition.MoreViolations
		if errors.As(e, &more) {
			t.Fatalf("the list of violations was cut (%v): the verdict of each rule cannot be read from it", e)
		}
		var v *edition.Violation
		if errors.As(e, &v) && v.Rule == rule {
			out = append(out, v)
		}
	}
	walk(err)
	return out
}

// crossKnown is one known violation of the shingle rule of B14 (amendment 28): the file of the
// template of challenge cid whose overlap with the file otherFile of the template of challenge
// other is at or above theta.
type crossKnown struct {
	cid, file, other, otherFile string
}

// crossKnownB14 are the violations of B14 that the real tree is known to have, and the only ones it
// may have (ADR-0056, the row of A7-x): 51-nimbus-desk-egress's falco-alerts.jsonl holds the lines
// of three alerts of 50-nimbus-desk-triage's falco-events.jsonl word for word. PR 6 (the rewrite of
// challenge 51) makes this table empty. The check has no exception for them: an event edition of
// these templates is refused by `edition check` (fail-closed). The table is this test's expectation
// only, so that a new violation is red, and so is one of the table that is no longer reported.
var crossKnownB14 = []crossKnown{
	{cid: crossIRB, file: "falco-alerts.jsonl", other: crossIRA, otherFile: "falco-events.jsonl"},
}

// matches reports whether v is the known violation k: B14's shingle rule, on k's pair of files.
func (k crossKnown) matches(v *edition.Violation) bool {
	return v.Rule == edition.RuleCrossShare && v.CID == k.cid && v.File == k.file &&
		strings.Contains(v.Msg, "shingle overlap") &&
		strings.Contains(v.Msg, " with file "+k.otherFile+" of the template of challenge "+k.other+" ")
}

// crossKnownProblems is how the violations of B14 inside err differ from crossKnownB14: one line
// per violation that is not in the table, and one per entry of the table that is not reported.
func crossKnownProblems(t *testing.T, err error) []string {
	t.Helper()
	matched := make([]bool, len(crossKnownB14))
	var out []string
	for _, v := range crossViolationList(t, err, edition.RuleCrossShare) {
		found := false
		for i, k := range crossKnownB14 {
			if !matched[i] && k.matches(v) {
				matched[i], found = true, true
				break
			}
		}
		if !found {
			out = append(out, "a violation of B14 that is not a known one (crossKnownB14): "+v.Error())
		}
	}
	for i, k := range crossKnownB14 {
		if !matched[i] {
			out = append(out, "the known violation of B14 ("+k.cid+" "+k.file+" with "+k.other+" "+k.otherFile+") is no longer reported: it is fixed, so remove it from crossKnownB14 (ADR-0056 A7-x, PR 6)")
		}
	}
	return out
}

// V107 to V110 (1): every scope of the real tree with two investigate challenges or more meets B13,
// B15 and B16, and B14 but for the known violations of its shingle rule (crossKnownB14, exactly
// those), rule by rule; the scope of ir-nimbus-desk is one of them and compared something of each.
func TestCrossChallenge_TheRealTreeMeetsB13ToB16(t *testing.T) {
	scopes := crossRealScopes(t)
	ir, ok := scopes[crossIRScenario]
	if !ok {
		t.Fatalf("there is no scenario %s: V107 to V110 pin that its two challenges are compared", crossIRScenario)
	}
	if _, a := ir[crossIRA]; !a {
		t.Fatalf("the scope of %s does not hold %s", crossIRScenario, crossIRA)
	}
	if _, b := ir[crossIRB]; !b {
		t.Fatalf("the scope of %s does not hold %s", crossIRScenario, crossIRB)
	}
	compared := 0
	for _, name := range slices.Sorted(maps.Keys(scopes)) {
		chs := crossPracticeScope(t, scopes[name])
		if len(chs) < 2 {
			continue
		}
		compared++
		rep, err := edition.CheckCrossChallenge(chs)
		for _, rule := range crossRules {
			t.Run(name+"/"+rule, func(t *testing.T) {
				if rule == edition.RuleCrossShare {
					for _, p := range crossKnownProblems(t, err) {
						t.Error(p)
					}
					return
				}
				for _, v := range crossViolations(t, err, rule) {
					t.Error(v)
				}
			})
		}
		if name == crossIRScenario {
			// The two ordered pairs of seat *, the declared file, the declared timeline, and the
			// answer windows: none of them may be a comparison of nothing.
			if rep.AnswerPairs < 2 || rep.Shared < 1 || rep.FilePairs < 1 || rep.Timelines < 1 || rep.Windows < 1 {
				t.Errorf("%s: B13 to B16 compared %+v; want two answer pairs and at least one of the others", name, rep)
			}
		}
	}
	if compared == 0 {
		t.Error("no scope of the real tree has two investigate challenges: B13 to B16 compared nothing")
	}
}

// cloneCross is a copy of chs whose templates, bundles, declarations and edition.yaml can be
// changed without changing chs (the answers are shared: no case changes them).
func cloneCross(chs map[string]*edition.CrossChallenge) map[string]*edition.CrossChallenge {
	files := func(in []edition.BundleFile) []edition.BundleFile {
		out := make([]edition.BundleFile, len(in))
		for i, f := range in {
			out[i] = edition.BundleFile{Name: f.Name, Data: slices.Clone(f.Data)}
		}
		return out
	}
	out := make(map[string]*edition.CrossChallenge, len(chs))
	for id, ch := range chs {
		c := *ch
		c.Template = files(ch.Template)
		c.Bundles = nil
		for _, b := range ch.Bundles {
			c.Bundles = append(c.Bundles, &edition.Bundle{Seat: b.Seat, CID: b.CID, Files: files(b.Files)})
		}
		c.Evidence.Shares = slices.Clone(ch.Evidence.Shares)
		spec := *ch.Spec
		c.Spec = &spec
		out[id] = &c
	}
	return out
}

// crossTimeRE is a literal time as B15 and B16 read one: a timestamp word, with no token byte
// (B7's TOKEN, [A-Za-z0-9._:/-]) before or after it.
var crossTimeRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9._:/-])([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)(?:$|[^A-Za-z0-9._:/-])`)

// crossTimes is the literal times of the files, in order of the files and of the text.
func crossTimes(files []edition.BundleFile) []string {
	var out []string
	for _, f := range files {
		for _, line := range strings.Split(string(f.Data), "\n") {
			for _, m := range crossTimeRE.FindAllStringSubmatch(line, -1) {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// crossShift is the time word w moved by d.
func crossShift(t *testing.T, w string, d time.Duration) string {
	t.Helper()
	at, err := time.Parse(time.RFC3339, w)
	if err != nil {
		t.Fatalf("a time of the template does not parse: %v", err)
	}
	return at.Add(d).UTC().Format(time.RFC3339)
}

// crossSharedName is the file that b declares it shares with a (the test needs one).
func crossSharedName(t *testing.T, chs map[string]*edition.CrossChallenge, a, b string) string {
	t.Helper()
	for _, s := range chs[b].Evidence.Shares {
		if s.With == a {
			return s.File
		}
	}
	t.Fatalf("%s declares no file shared with %s", b, a)
	return ""
}

// crossWindow is the first answer window of an edition.yaml: its time.base and its [from, to).
func crossWindow(t *testing.T, spec *edition.Spec) (time.Time, int64, int64) {
	t.Helper()
	base, err := time.Parse(time.RFC3339, spec.Time.Base)
	if err != nil {
		t.Fatalf("time.base does not parse: %v", err)
	}
	for _, sl := range spec.Slots {
		if sl.Role == edition.RoleAnswer && sl.Window != nil && sl.Window.From != nil && sl.Window.To != nil {
			return base, *sl.Window.From, *sl.Window.To
		}
	}
	t.Fatal("the edition has no answer slot with a window")
	return time.Time{}, 0, 0
}

// V107 to V110 (the copies): on the inputs of the scope of ir-nimbus-desk, each change below makes
// its rule name a violation that the unbroken inputs do not have.
func TestCrossChallenge_TheRealTreeCopiesAreRed(t *testing.T) {
	ir := crossRealScopes(t)[crossIRScenario]
	base := crossPracticeScope(t, ir)
	if base[crossIRA] == nil || base[crossIRB] == nil {
		t.Fatalf("the scope of %s does not hold %s and %s", crossIRScenario, crossIRA, crossIRB)
	}
	_, baseErr := edition.CheckCrossChallenge(base)
	shared := crossSharedName(t, base, crossIRA, crossIRB)
	appendLine := func(f *edition.BundleFile, line string) {
		f.Data = append(f.Data, []byte("\n"+line+"\n")...)
	}
	// firstOther is the first template file of the challenge that is not the shared file.
	firstOther := func(t *testing.T, ch *edition.CrossChallenge) *edition.BundleFile {
		t.Helper()
		for i := range ch.Template {
			if ch.Template[i].Name != shared {
				return &ch.Template[i]
			}
		}
		t.Fatal("the template has no file but the shared one")
		return nil
	}
	perSeatAnswer := func(t *testing.T, ch *edition.CrossChallenge) string {
		t.Helper()
		for _, q := range ch.Questions {
			if v := ch.Answers[edition.AnySeat][q.ID]; answerformat.PerSeat(q.Format) && v != "" {
				return v
			}
		}
		t.Fatal("the challenge has no per-seat answer of seat *")
		return ""
	}
	sharedOf := func(t *testing.T, ch *edition.CrossChallenge) *edition.BundleFile {
		t.Helper()
		for i := range ch.Template {
			if ch.Template[i].Name == shared {
				return &ch.Template[i]
			}
		}
		t.Fatalf("the template has no %s", shared)
		return nil
	}

	cases := []struct {
		name  string
		rule  string
		apply func(t *testing.T, chs map[string]*edition.CrossChallenge)
	}{
		// V107
		{"an answer of 50 in a file of 51's bundle", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			b := chs[crossIRB].Bundles[0]
			appendLine(&b.Files[0], perSeatAnswer(t, chs[crossIRA]))
		}},
		{"an answer of 51 in a file of 50's bundle", edition.RuleCrossAnswer, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			b := chs[crossIRA].Bundles[0]
			appendLine(&b.Files[0], perSeatAnswer(t, chs[crossIRB]))
		}},
		// V108
		{"one byte of the declared file changed on 51's side", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			f := sharedOf(t, chs[crossIRB])
			i := slices.IndexFunc(f.Data, func(c byte) bool { return c >= 'a' && c < 'z' })
			if i < 0 {
				t.Fatal("the shared file has no lower-case letter to change")
			}
			f.Data[i]++
		}},
		{"a slot mark in the declared file on both sides", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			for _, id := range []string{crossIRA, crossIRB} {
				f := sharedOf(t, chs[id])
				f.Data = append([]byte(edition.MarkOpen+"planted"+edition.MarkClose+" "), f.Data...)
			}
		}},
		{"the declaration removed", edition.RuleCrossShare, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			chs[crossIRB].Evidence.Shares = nil
		}},
		// V109
		{"a literal time of 50 moved, 51 not", edition.RuleCrossTimeline, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			inShared := crossTimes([]edition.BundleFile{*sharedOf(t, chs[crossIRA])})
			var aOther []edition.BundleFile
			for _, f := range chs[crossIRA].Template {
				if f.Name != shared {
					aOther = append(aOther, f)
				}
			}
			inA := crossTimes(aOther)
			var bOther []edition.BundleFile
			for _, f := range chs[crossIRB].Template {
				if f.Name != shared {
					bOther = append(bOther, f)
				}
			}
			w := ""
			for _, c := range crossTimes(bOther) {
				if slices.Contains(inA, c) && !slices.Contains(inShared, c) {
					w = c
					break
				}
			}
			if w == "" {
				t.Fatal("51 has no literal time of its own files that is in 50's files and not in the shared one")
			}
			moved := crossShift(t, w, time.Second)
			for i := range chs[crossIRA].Template {
				f := &chs[crossIRA].Template[i]
				if f.Name != shared {
					f.Data = []byte(strings.ReplaceAll(string(f.Data), w, moved))
				}
			}
		}},
		{"51 has a literal time that 50 does not", edition.RuleCrossTimeline, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			at, err := time.Parse(time.RFC3339, chs[crossIRB].Spec.Time.Base)
			if err != nil {
				t.Fatalf("time.base of 51 does not parse: %v", err)
			}
			w := at.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
			if slices.Contains(crossTimes(chs[crossIRA].Template), w) {
				t.Fatal("the planted time is a time of 50 already")
			}
			appendLine(firstOther(t, chs[crossIRB]), "note "+w+" planted")
		}},
		// V110
		{"time.base of 50 moved until the window holds a later literal time", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			// The least move (V110): the window's end passes the first literal time after the
			// window by one second, so the window holds that time and no other.
			base, _, to := crossWindow(t, chs[crossIRA].Spec)
			end := base.Add(time.Duration(to) * time.Second)
			var next time.Time
			for _, id := range []string{crossIRA, crossIRB} {
				for _, w := range crossTimes(chs[id].Template) {
					at, err := time.Parse(time.RFC3339, w)
					if err == nil && !at.Before(end) && (next.IsZero() || at.Before(next)) {
						next = at
					}
				}
			}
			if next.IsZero() {
				t.Fatal("no literal time after the window")
			}
			chs[crossIRA].Spec.Time.Base = next.Add(time.Second - time.Duration(to)*time.Second).UTC().Format(time.RFC3339)
		}},
		{"a literal time in 50's window added to 50's template", edition.RuleCrossWindow, func(t *testing.T, chs map[string]*edition.CrossChallenge) {
			base, from, _ := crossWindow(t, chs[crossIRA].Spec)
			appendLine(firstOther(t, chs[crossIRA]), "note "+base.Add(time.Duration(from+1)*time.Second).UTC().Format(time.RFC3339)+" planted")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chs := cloneCross(base)
			c.apply(t, chs)
			_, err := edition.CheckCrossChallenge(chs)
			was := crossViolations(t, baseErr, c.rule)
			var added []string
			for _, v := range crossViolations(t, err, c.rule) {
				if !slices.Contains(was, v) {
					added = append(added, v)
				}
			}
			if len(added) == 0 {
				t.Errorf("the copy is not refused by %s beyond the unbroken inputs (%v)", c.rule, err)
			}
		})
	}
	// The cases change copies only: the inputs read from the tree are as they were.
	if _, err := edition.CheckCrossChallenge(base); !slices.Equal(crossViolations(t, err, edition.RuleCrossShare), crossViolations(t, baseErr, edition.RuleCrossShare)) {
		t.Error("a case changed the unbroken inputs")
	}
}
