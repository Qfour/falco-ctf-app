package catalog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// ADR-0056 stage A1 (V10 and the catalog side of V6): the `investigate` type,
// its strict block, and the load-time checks. Fixtures are written under
// t.TempDir(); no challenge under challenges/ uses the type yet.

const (
	invMount = "/opt/ctf/evidence"
	// one good question: a 16-digit hexid (space 16^16, attempts default 5)
	invHexQ = "    - id: q1\n      format: hexid\n      params: {length: 16}\n"
)

// inv builds a falco-rule.yaml of an investigate challenge. extra is inserted
// before the type line (top-level keys); evidence is the whole `evidence:` value.
func inv(extra, evidence, questions string) string {
	return extra + "type: " + catalog.TypeInvestigate + "\ninvestigate:\n  evidence: " + evidence + "\n  questions:\n" + questions
}

func evMount(dir string) string { return "{mountDir: " + dir + "}" }

func TestLoad_Investigate_Valid(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount),
		invHexQ+
			"    - id: q-choice\n      format: choice-set\n      attempts: 10\n"+
			"      params: {choices: [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10]}\n"+
			"    - id: q-window\n      format: timestamp\n      attempts: 3\n      params: {windowSeconds: 3600}\n"+
			"    - id: q-path\n      format: path\n"+
			"    - id: q-seq\n      format: sequence\n      attempts: 1\n"+
			"      params: {labels: [a, b, c, d, e, f], length: 3}\n"))
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ch := cat["14-ir-demo"]
	if ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
		t.Fatalf("type %q, block %v", ch.Type, ch.Investigate)
	}
	if ch.Investigate.Evidence.MountDir != invMount {
		t.Errorf("mountDir = %q", ch.Investigate.Evidence.MountDir)
	}
	wantAttempts := map[string]int{"q1": catalog.DefaultAttempts, "q-choice": 10, "q-window": 3, "q-path": catalog.DefaultAttempts, "q-seq": 1}
	qs := ch.Investigate.Questions
	if len(qs) != len(wantAttempts) {
		t.Fatalf("%d questions, want %d", len(qs), len(wantAttempts))
	}
	for _, q := range qs {
		if q.Attempts != wantAttempts[q.ID] {
			t.Errorf("question %q attempts = %d, want %d", q.ID, q.Attempts, wantAttempts[q.ID])
		}
	}
	if qs[0].ID != "q1" || qs[4].ID != "q-seq" {
		t.Errorf("question order changed: %v", qs)
	}
}

// V10: every one of these is a load failure, for the reason named.
func TestLoad_Investigate_RejectsMalformedBlocks(t *testing.T) {
	ok := func(q string) string { return inv("", evMount(invMount), q) }
	manyQs := strings.Repeat(invHexQ, 1)
	for i := 2; i <= 9; i++ { // q1 plus q2..q9 = 9 questions
		manyQs += strings.Replace(invHexQ, "q1", "q"+string(rune('0'+i)), 1)
	}
	cases := []struct {
		name string
		yaml string
		want string
	}{
		// strict decode: an unknown key at any depth
		{"unknown key under investigate", "type: " + catalog.TypeInvestigate + "\ninvestigate:\n  extra: 1\n  evidence: " + evMount(invMount) + "\n  questions:\n" + invHexQ, "field extra not found"},
		{"unknown key under evidence", inv("", "{mountDir: "+invMount+", perm: 444}", invHexQ), "field perm not found"},
		{"answer key under a question", ok(invHexQ + "      answer: deadbeef\n"), "field answer not found"},
		{"unknown key under params", ok("    - id: q1\n      format: hexid\n      params: {length: 16, bogus: 1}\n"), "field bogus not found"},
		{"attempts is not a number", ok("    - id: q1\n      format: hexid\n      attempts: five\n      params: {length: 16}\n"), "investigate block"},
		// flag / rule keys must be empty
		{"expectedFlag set", inv("expectedFlag: FALCO{abc}\n", evMount(invMount), invHexQ), "expectedFlag must be empty"},
		{"expectedRules set", inv("expectedRules: [r]\n", evMount(invMount), invHexQ), "expectedRules/forbiddenRules must be empty"},
		{"forbiddenRules set", inv("forbiddenRules: [r]\n", evMount(invMount), invHexQ), "expectedRules/forbiddenRules must be empty"},
		{"requireExfil set", inv("requireExfil: true\n", evMount(invMount), invHexQ), "requireExfil"},
		{"requireExpectedRuleFire set", inv("requireExpectedRuleFire: true\n", evMount(invMount), invHexQ), "requireExpectedRuleFire"},
		{"detect block set", inv("detect: {evasionCapture: a.scap, benignCapture: b.scap}\n", evMount(invMount), invHexQ), "detect block must be absent"},
		{"no investigate block", "type: " + catalog.TypeInvestigate + "\n", "investigate block is required"},
		// questions
		{"no questions", ok("    []\n"), "questions needs 1..8"},
		{"nine questions", ok(manyQs), "questions needs 1..8"},
		{"qid outside the grammar", ok(strings.Replace(invHexQ, "q1", "Q1", 1)), "outside ^[a-z]"},
		{"qid duplicated", ok(invHexQ + invHexQ), "duplicate question id"},
		{"format outside the list", ok("    - id: q1\n      format: regex\n"), "is not one of"},
		{"format missing", ok("    - id: q1\n      params: {length: 16}\n"), "is not one of"},
		{"params key of another format", ok("    - id: q1\n      format: hexid\n      params: {length: 16, windowSeconds: 5}\n"), "hexid takes only params.length"},
		{"params on a format that takes none", ok("    - id: q1\n      format: path\n      params: {length: 3}\n"), "takes no params"},
		{"hexid length out of range", ok("    - id: q1\n      format: hexid\n      params: {length: 8}\n"), "params.length in 12..64"},
		{"attempts 0", ok(invHexQ + "      attempts: 0\n"), "attempts must be in 1..10"},
		{"attempts -1", ok(invHexQ + "      attempts: -1\n"), "attempts must be in 1..10"},
		{"attempts 11", ok(invHexQ + "      attempts: 11\n"), "attempts must be in 1..10"},
		// D3 (a) / V6 (catalog side)
		{"4-option choice-set (15 < 100 x 5)", ok("    - id: q1\n      format: choice-set\n      params: {choices: [a, b, c, d]}\n"), "below 100 x attempts"},
		{"9-option choice-set at 6 attempts (511 < 600)", ok("    - id: q1\n      format: choice-set\n      attempts: 6\n      params: {choices: [a, b, c, d, e, f, g, h, i]}\n"), "below 100 x attempts"},
		{"timestamp window 499 at the default 5 attempts", ok("    - id: q1\n      format: timestamp\n      params: {windowSeconds: 499}\n"), "below 100 x attempts"},
		{"technique cannot be sized", ok("    - id: q1\n      format: technique\n"), "cannot be computed"},
		// mountDir
		{"mountDir empty", inv("", `{mountDir: ""}`, invHexQ), "must not be empty"},
		{"mountDir missing", inv("", "{}", invHexQ), "must not be empty"},
		{"mountDir relative", inv("", evMount("evidence"), invHexQ), "absolute, clean path"},
		{"mountDir is /", inv("", evMount("/"), invHexQ), "absolute, clean path"},
		{"mountDir trailing slash", inv("", evMount("/opt/ctf/evidence/"), invHexQ), "absolute, clean path"},
		{"mountDir doubled slash", inv("", evMount("/opt//evidence"), invHexQ), "absolute, clean path"},
		{"mountDir with ..", inv("", evMount("/opt/../etc"), invHexQ), "absolute, clean path"},
		{"mountDir character outside the set", inv("", evMount("/opt/ctf/ev idence"), invHexQ), "outside [A-Za-z0-9._-]"},
		{"mountDir is the missions dir", inv("", evMount("/opt/ctf/missions"), invHexQ), "overlaps /opt/ctf/missions"},
		{"mountDir under the missions dir", inv("", evMount("/opt/ctf/missions/x"), invHexQ), "overlaps /opt/ctf/missions"},
		{"mountDir above the missions dir", inv("", evMount("/opt/ctf"), invHexQ), "overlaps /opt/ctf/missions"},
		{"mountDir is the seed root", inv("", evMount("/plant-seed"), invHexQ), "overlaps /plant-seed"},
		{"mountDir under the seed root", inv("", evMount("/plant-seed/a"), invHexQ), "overlaps /plant-seed"},
		{"mountDir under the snapshot root", inv("", evMount("/opt/ctf/plant-seed/a"), invHexQ), "overlaps /opt/ctf/plant-seed"},
		// V44 (ADR-0056 D11): where the plant initContainer sees the evidence Secrets
		{"mountDir is the evidence source root", inv("", evMount("/opt/ctf/evidence-src"), invHexQ), "overlaps /opt/ctf/evidence-src"},
		{"mountDir under the evidence source root", inv("", evMount("/opt/ctf/evidence-src/14-ir-demo"), invHexQ), "overlaps /opt/ctf/evidence-src"},
		// the block belongs to this type only
		{"investigate block on a trigger", "type: trigger\nexpectedRules: [r]\ninvestigate:\n  evidence: " + evMount(invMount) + "\n  questions:\n" + invHexQ, "belongs to type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeChallenge(t, dir, "14-ir-demo", c.yaml)
			_, err := catalog.Load(dir)
			wantLoadError(t, err, c.want)
		})
	}
}

func TestLoad_Investigate_AcceptsPlainMountDirs(t *testing.T) {
	// the sibling "/opt/ctf/evidence-srcx" shares the evidence source root's prefix
	// but not its path element: it is plain, like "/opt/ctf/missions-extra"
	for _, m := range []string{"/opt/ctf/evidence", "/srv/ir/bundle", "/opt/ctf/missions-extra", "/var/lib/evidence.d", "/opt/ctf/evidence-srcx"} {
		dir := t.TempDir()
		writeChallenge(t, dir, "14-ir-demo", inv("", evMount(m), invHexQ))
		if _, err := catalog.Load(dir); err != nil {
			t.Errorf("mountDir %s: %v", m, err)
		}
	}
}

// V6 (catalog): the boundary that the 4-option refusal sits next to.
func TestLoad_Investigate_SpaceBoundary(t *testing.T) {
	dir := t.TempDir()
	// invHexQ is the per-seat question V20 needs, so only the choice-set is under test.
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount), invHexQ+invChoiceQ))
	if _, err := catalog.Load(dir); err != nil {
		t.Fatalf("n = 10 options at 10 attempts (1023 >= 1000) must load: %v", err)
	}
}

const invChoiceQ = "    - id: q2\n      format: choice-set\n      attempts: 10\n" +
	"      params: {choices: [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10]}\n"

const invSeqQ = "    - id: q3\n      format: sequence\n      attempts: 1\n" +
	"      params: {labels: [a, b, c, d, e, f], length: 3}\n"

// V20 (ADR-0056 D1): every investigate challenge has at least one question whose
// format can vary per seat; fixed-answer questions alone could be solved by
// sharing the answers on the Board.
func TestLoad_Investigate_V20_NeedsAPerSeatQuestion(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount), invChoiceQ+invSeqQ))
	_, err := catalog.Load(dir)
	wantLoadError(t, err, "can vary per seat")

	for name, q := range map[string]string{
		"hexid":     invHexQ,
		"timestamp": "    - id: q1\n      format: timestamp\n      params: {windowSeconds: 3600}\n",
		"path":      "    - id: q1\n      format: path\n",
		"name":      "    - id: q1\n      format: name\n",
	} {
		d := t.TempDir()
		writeChallenge(t, d, "14-ir-demo", inv("", evMount(invMount), invChoiceQ+invSeqQ+q))
		if _, err := catalog.Load(d); err != nil {
			t.Errorf("fixed questions plus one %s question must load: %v", name, err)
		}
	}
}

// V21: path / name are sized by the edition vocabulary, not by the catalog, so
// the catalog passes them (explicitly, on ErrSpaceFromVocabulary) even at the
// largest attempts; technique stays refused (no ATT&CK table: ErrSpaceUnavailable).
func TestLoad_Investigate_V21_VocabularySpaceIsDeferredTechniqueIsRefused(t *testing.T) {
	for _, f := range []string{"path", "name"} {
		dir := t.TempDir()
		writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount),
			"    - id: q1\n      format: "+f+"\n      attempts: 10\n"))
		if _, err := catalog.Load(dir); err != nil {
			t.Errorf("%s at 10 attempts must load (sized by the edition validator): %v", f, err)
		}
	}
	dir := t.TempDir()
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount),
		invHexQ+"    - id: q2\n      format: technique\n"))
	_, err := catalog.Load(dir)
	wantLoadError(t, err, "cannot be computed")
}

// V25 (ADR-0056 D1): for an investigate challenge the falco-rule.yaml top level is
// strict too, so a key that looks like an answer cannot load and sit ignored in a
// public file. The existing types keep their lenient decode.
func TestLoad_Investigate_V25_TopLevelIsStrict(t *testing.T) {
	for _, c := range []struct{ key, name string }{
		{"futureKey: 1\n", "futureKey"},
		{"answer: deadbeef\n", "answer"},
		{"expectedFlg: FALCO{x}\n", "expectedFlg"},
	} {
		dir := t.TempDir()
		writeChallenge(t, dir, "14-ir-demo", inv(c.key, evMount(invMount), invHexQ))
		_, err := catalog.Load(dir)
		wantLoadError(t, err, "field "+c.name+" not found")
	}
	// control: the same file without the key loads
	ok := t.TempDir()
	writeChallenge(t, ok, "14-ir-demo", inv("", evMount(invMount), invHexQ))
	if _, err := catalog.Load(ok); err != nil {
		t.Fatalf("the control file must load: %v", err)
	}
}

const invAttack = "attack:\n  tactic: \"Discovery\"\n  techniqueId: \"T1083\"\n  techniqueName: \"File and Directory Discovery\"\n"

// V25 and gen-attack-layer.py: every challenge carries a top-level `attack:` block
// (make gen-attack refuses a challenge without it), so the strict schema of an
// investigate challenge must accept it, or the type could not satisfy the catalog
// and gen-attack at once. Inside the block the decode is strict as well.
func TestLoad_Investigate_V25_AttackBlockIsAccepted(t *testing.T) {
	ok := t.TempDir()
	writeChallenge(t, ok, "14-ir-demo", inv(invAttack, evMount(invMount), invHexQ))
	if _, err := catalog.Load(ok); err != nil {
		t.Fatalf("an investigate challenge with a complete attack block must load: %v", err)
	}
	for _, c := range []struct{ name, extra, want string }{
		{"unknown key inside attack", invAttack + "  subTechnique: x\n", "field subTechnique not found"},
		{"answer inside attack", invAttack + "  answer: deadbeef\n", "field answer not found"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeChallenge(t, dir, "14-ir-demo", inv(c.extra, evMount(invMount), invHexQ))
			_, err := catalog.Load(dir)
			wantLoadError(t, err, c.want)
		})
	}
}

func TestLoad_V25_OtherTypesKeepTheLenientDecode(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "01-a", "type: trigger\nexpectedRules: [r]\nfutureKey: 1\nattack: {tactic: x}\n")
	writeChallenge(t, dir, "02-b", "type: evade\nexpectedFlag: FALCO{dev-b}\nfutureKey: 1\n")
	if _, err := catalog.Load(dir); err != nil {
		t.Fatalf("an unknown top-level key must still load for the existing types: %v", err)
	}
}

func TestLoad_UnknownTypeMessageNamesTheInvestigateType(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "01-a", "type: quiz\n")
	_, err := catalog.Load(dir)
	wantLoadError(t, err, catalog.TypeInvestigate)
}

// ADR-0056 V21, reversed by A3b-3: the scoreboard now has a grader for the type
// (Grader.SubmitAnswer behind the answer route), so LoadScored (the only door
// cmd/scoreboard uses) accepts an investigate challenge in scope, whole catalog or a
// scenario that lists it, with or without the event's flags file. The answers table
// the event mode needs is edition.Load's check (D8), not the catalog's.
func TestLoadScored_AcceptsAnInvestigateChallengeInScope(t *testing.T) {
	dir := t.TempDir()
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount), invHexQ))
	writeChallenge(t, dir, "01-a", "type: trigger\nexpectedRules: [r]\n")
	writeChallenge(t, dir, "02-b", "type: evade\nexpectedFlag: FALCO{dev-b}\nforbiddenRules: [r]\n")
	if _, err := catalog.Load(dir); err != nil {
		t.Fatalf("Load itself must accept the type: %v", err)
	}

	// no scenario: the whole catalog, ordered by id
	scored, err := catalog.LoadScored(dir, "", "")
	if err != nil {
		t.Fatalf("LoadScored must accept an investigate challenge in scope: %v", err)
	}
	if ch, ok := scored.Catalog["14-ir-demo"]; !ok || ch.Type != catalog.TypeInvestigate || ch.Investigate == nil {
		t.Fatalf("the scored catalog lost the investigate challenge: %+v (present=%v)", ch, ok)
	}
	if got := strings.Join(scored.Order, ","); got != "01-a,02-b,14-ir-demo" {
		t.Fatalf("Order = %s, want 01-a,02-b,14-ir-demo", got)
	}

	// a scenario that lists it
	sc := catalog.WriteScenarioFor(t, t.TempDir(), dir, "ir", "01-a", "14-ir-demo")
	scored, err = catalog.LoadScored(dir, sc, "")
	if err != nil {
		t.Fatalf("a scenario with the investigate challenge must load: %v", err)
	}
	if got := strings.Join(scored.Order, ","); got != "01-a,14-ir-demo" || scored.Catalog["14-ir-demo"].Type != catalog.TypeInvestigate {
		t.Fatalf("scenario order = %s, catalog = %v", got, scored.Catalog.IDs())
	}

	// the event mode (a flags file): the evade challenge outside the scope is
	// validated and not applied; the investigate challenge has no flag and needs none
	flags := filepath.Join(t.TempDir(), "flags.yaml")
	if err := os.WriteFile(flags, []byte("flags:\n  02-b: FALCO{test-a3b3-b}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scored, err = catalog.LoadScored(dir, sc, flags)
	if err != nil {
		t.Fatalf("a flags file with a scope of a trigger and an investigate challenge must load: %v", err)
	}
	if ch := scored.Catalog["14-ir-demo"]; ch.ExpectedFlag != "" {
		t.Fatalf("the investigate challenge was given a flag: %q", ch.ExpectedFlag)
	}

	// out of scope: a scenario that does not list it is fine, as before
	sc = catalog.WriteScenarioFor(t, t.TempDir(), dir, "only-a", "01-a")
	scored, err = catalog.LoadScored(dir, sc, "")
	if err != nil {
		t.Fatalf("a scenario without the investigate challenge must load: %v", err)
	}
	if _, ok := scored.Catalog["14-ir-demo"]; ok {
		t.Fatal("restricted catalog still holds the investigate challenge")
	}
}

// a7Challenge is the first investigate challenge of the real tree (ADR-0056 A7).
const a7Challenge = "50-nimbus-desk-triage"

// Regression: the real challenges and every real scenario load. V27: the number of
// real challenges is not pinned (adding a mission must not turn this red); only "not
// empty" is, and, since A7, "contains the A7 challenge as an investigate challenge"
// (it was "no investigate challenge" before A7). The investigate block is only on
// investigate challenges (the decode refuses it elsewhere, so this holds the tree).
func TestRealTree_LoadsUnchangedByTheNewType(t *testing.T) {
	cat, err := catalog.Load("../../challenges")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cat) == 0 {
		t.Fatal("the real challenge tree loaded as empty: the path is wrong or the catalog was emptied")
	}
	a7, ok := cat[a7Challenge]
	switch {
	case !ok:
		t.Errorf("the real tree has no %s (ADR-0056 A7)", a7Challenge)
	case a7.Type != catalog.TypeInvestigate || a7.Investigate == nil:
		t.Errorf("%s is type %q, want an investigate challenge with its block (ADR-0056 A7)", a7Challenge, a7.Type)
	}
	for id, ch := range cat {
		if (ch.Type == catalog.TypeInvestigate) != (ch.Investigate != nil) {
			t.Errorf("%s: type %q and investigate block present = %v disagree", id, ch.Type, ch.Investigate != nil)
		}
	}
	scenarios, err := filepath.Glob("../../scenarios/*/scenario.yaml")
	if err != nil || len(scenarios) < 3 {
		t.Fatalf("scenario glob: %v %v", scenarios, err)
	}
	for _, sc := range scenarios {
		scored, err := catalog.LoadScored("../../challenges", sc, "")
		if err != nil {
			t.Errorf("LoadScored(%s): %v", sc, err)
			continue
		}
		if _, err := catalog.LoadJourneys("../../challenges", scored.Catalog); err != nil {
			t.Errorf("LoadJourneys(%s): %v", sc, err)
		}
	}
}

// ---- journey questions[] (ADR-0056 D1) ----

func invCatalog(t *testing.T, questions string) catalog.Catalog {
	t.Helper()
	dir := t.TempDir()
	writeChallenge(t, dir, "14-ir-demo", inv("", evMount(invMount), questions))
	cat, err := catalog.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cat
}

const invTwoQ = invHexQ + "    - id: q2\n      format: hexid\n      params: {length: 16}\n"

func TestLoadJourneys_Questions_SetMustMatchTheCatalog(t *testing.T) {
	cat := invCatalog(t, invTwoQ)
	head := "challengeId: 14-ir-demo\ntitle: IR\nquestions:\n"
	cases := []struct {
		name string
		yaml string
		want string // "" = loads
	}{
		{"both questions, any order", head + "  - {id: q2, prompt: second}\n  - {id: q1, prompt: first}\n", ""},
		{"a question missing", head + "  - {id: q1, prompt: first}\n", "1 of the challenge's 2"},
		{"an id the catalog does not have", head + "  - {id: q1, prompt: a}\n  - {id: q3, prompt: c}\n", "not a question of the challenge"},
		{"an id twice", head + "  - {id: q1, prompt: a}\n  - {id: q1, prompt: b}\n", "appears twice"},
		{"an empty prompt", head + "  - {id: q1, prompt: a}\n  - {id: q2, prompt: '  '}\n", "empty prompt"},
		{"an answer key", head + "  - {id: q1, prompt: a, answer: deadbeef}\n  - {id: q2, prompt: b}\n", "field answer not found"},
		{"no questions at all", "challengeId: 14-ir-demo\ntitle: IR\n", "0 of the challenge's 2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeJourney(t, dir, "14-ir-demo", c.yaml)
			js, err := catalog.LoadJourneys(dir, cat)
			if c.want == "" {
				if err != nil {
					t.Fatalf("LoadJourneys: %v", err)
				}
				if len(js["14-ir-demo"].Questions) != 2 {
					t.Fatalf("questions = %v", js["14-ir-demo"].Questions)
				}
				return
			}
			wantLoadError(t, err, c.want)
		})
	}
}

func TestLoadJourneys_Questions_AnInvestigateChallengeNeedsAJourney(t *testing.T) {
	cat := invCatalog(t, invHexQ)
	_, err := catalog.LoadJourneys(t.TempDir(), cat)
	wantLoadError(t, err, "has no journey.yaml")
}

// V25 (#608): LoadJourneys returns early when the journey dir itself does not
// exist (the graceful degrade of every other type); an investigate challenge must
// still be refused on that path, not slip through as "no journeys".
func TestLoadJourneys_V25_NoJourneyDirAtAllStillFailsAnInvestigateChallenge(t *testing.T) {
	cat := invCatalog(t, invHexQ)
	missing := filepath.Join(t.TempDir(), "no-such-journey-dir")
	_, err := catalog.LoadJourneys(missing, cat)
	wantLoadError(t, err, "has no journey.yaml")

	// control: the same missing dir is still fine without an investigate challenge
	js, err := catalog.LoadJourneys(missing, journeyCatalog())
	if err != nil || len(js) != 0 {
		t.Fatalf("a missing journey dir must stay graceful for the other types: %v %v", js, err)
	}
	// and a directory that exists but holds another challenge's journey only
	other := t.TempDir()
	writeJourney(t, other, "01-initial-recon", "title: t\n")
	both := journeyCatalog()
	for id, ch := range cat {
		both[id] = ch
	}
	_, err = catalog.LoadJourneys(other, both)
	wantLoadError(t, err, "14-ir-demo")
}

// V25: an investigate challenge's journey.yaml top level is strict. The existing
// types keep the lenient decode (an unknown key is ignored, as before).
func TestLoadJourneys_V25_TopLevelIsStrictForAnInvestigateChallenge(t *testing.T) {
	cat := invCatalog(t, invTwoQ)
	qs := "questions:\n  - {id: q1, prompt: first}\n  - {id: q2, prompt: second}\n"
	for _, key := range []string{"answer: deadbeef\n", "futureKey: 1\n", "solution: x\n"} {
		dir := t.TempDir()
		writeJourney(t, dir, "14-ir-demo", "challengeId: 14-ir-demo\ntitle: IR\n"+key+qs)
		_, err := catalog.LoadJourneys(dir, cat)
		wantLoadError(t, err, "not found in type catalog.Journey")
	}
	ok := t.TempDir()
	writeJourney(t, ok, "14-ir-demo", "challengeId: 14-ir-demo\ntitle: IR\n"+qs)
	if _, err := catalog.LoadJourneys(ok, cat); err != nil {
		t.Fatalf("the control journey must load: %v", err)
	}

	lenient := t.TempDir()
	writeJourney(t, lenient, "01-initial-recon", "title: t\nfutureKey: 1\n")
	if _, err := catalog.LoadJourneys(lenient, journeyCatalog()); err != nil {
		t.Fatalf("an unknown key in a trigger journey must still load: %v", err)
	}
}

// V25: the mapping elements of hints[] are strict too for an investigate
// challenge (JourneyHints decodes them leniently on its own, so an `answer:` key
// there would otherwise sit ignored); the structured and the legacy scalar form
// both still load, and a trigger journey keeps the lenient decode.
func TestLoadJourneys_V25_HintElementsAreStrictForAnInvestigateChallenge(t *testing.T) {
	cat := invCatalog(t, invTwoQ)
	head := "challengeId: 14-ir-demo\ntitle: IR\nquestions:\n  - {id: q1, prompt: first}\n  - {id: q2, prompt: second}\n"

	good := t.TempDir()
	writeJourney(t, good, "14-ir-demo", head+"hints:\n  - a legacy scalar hint\n  - {kind: command, text: look at the log, ruleRefs: [r], cheatsheetRef: c}\n")
	if _, err := catalog.LoadJourneys(good, cat); err != nil {
		t.Fatalf("scalar and structured hints must load: %v", err)
	}

	bad := t.TempDir()
	writeJourney(t, bad, "14-ir-demo", head+"hints:\n  - a legacy scalar hint\n  - {kind: command, text: look at the log, answer: deadbeef}\n")
	_, err := catalog.LoadJourneys(bad, cat)
	wantLoadError(t, err, "hints[1]")
	wantLoadError(t, err, "field answer not found")

	lenient := t.TempDir()
	writeJourney(t, lenient, "01-initial-recon", "title: t\nhints:\n  - {kind: rule, text: x, future: 1}\n")
	if _, err := catalog.LoadJourneys(lenient, journeyCatalog()); err != nil {
		t.Fatalf("an unknown key in a trigger journey's hint must still load: %v", err)
	}
}

func TestLoadJourneys_Questions_OtherTypesHaveNone(t *testing.T) {
	dir := t.TempDir()
	writeJourney(t, dir, "01-initial-recon", "title: t\nquestions:\n  - {id: q1, prompt: p}\n")
	_, err := catalog.LoadJourneys(dir, journeyCatalog())
	wantLoadError(t, err, "belongs to type")
}
