package catalog

// ADR-0056 V25: an investigate challenge's falco-rule.yaml and journey.yaml are
// decoded strictly (an unknown top-level key fails the load). A strict schema is only
// safe if it covers every key that ANY consumer of the file needs: the real files
// are the evidence of which keys those are (gen-attack-layer.py requires the
// top-level `attack:` block of every challenge; the journey UI reads the journey keys).
// So the strict schemas are run over every real file here: a key a real file uses
// that the schema does not know is red, which is what an investigate challenge
// written like the real ones would hit.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func realFiles(t *testing.T, name string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "challenges", "*", name))
	if err != nil || len(files) == 0 {
		t.Fatalf("no real %s found (glob error %v): the path is wrong or the tree was emptied", name, err)
	}
	return files
}

func topLevelKeys(t *testing.T, data []byte) []string {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		t.Fatalf("not a mapping document")
	}
	var keys []string
	m := doc.Content[0].Content
	for i := 0; i+1 < len(m); i += 2 {
		keys = append(keys, m[i].Value)
	}
	return keys
}

func TestStrictSchemas_CoverEveryRealFile(t *testing.T) {
	usedAttack := 0
	for _, f := range realFiles(t, "falco-rule.yaml") {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeStrictBytes(data, &ruleFileKeys{}); err != nil {
			t.Errorf("%s: the strict schema of an investigate challenge rejects a key this real file uses: %v", f, err)
		}
		for _, k := range topLevelKeys(t, data) {
			if k == "attack" {
				usedAttack++
			}
		}
		// the check can fail: the same bytes plus one unknown key are refused
		if err := decodeStrictBytes(append(data, []byte("\nzzzUnknownKey: 1\n")...), &ruleFileKeys{}); err == nil {
			t.Errorf("%s: an unknown top-level key was accepted by the strict schema", f)
		}
	}
	if usedAttack == 0 {
		t.Fatal("no real falco-rule.yaml has an attack: block: the evidence this test stands on is gone")
	}

	for _, f := range realFiles(t, "journey.yaml") {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkJourneyStrict(data); err != nil {
			t.Errorf("%s: the strict schema of an investigate journey rejects a key this real file uses: %v", f, err)
		}
		if err := checkJourneyStrict(append(data, []byte("\nzzzUnknownKey: 1\n")...)); err == nil {
			t.Errorf("%s: an unknown top-level key was accepted by the strict journey schema", f)
		}
	}
}

// Every key the strict rule-file schema knows is spelled once in Challenge or in
// the attack block: a stray duplicate (an `attack` field added to Challenge as well)
// would make yaml.v3 refuse the type at decode, so the schema is checked to be
// decodable at all with a file that uses its keys.
func TestRuleFileKeys_AttackBlockDecodes(t *testing.T) {
	src := "challengeId: 90-x\ntype: investigate\nattack:\n  tactic: t\n  techniqueId: i\n  techniqueName: n\n"
	var k ruleFileKeys
	if err := decodeStrictBytes([]byte(src), &k); err != nil {
		t.Fatal(err)
	}
	if k.Attack == nil || k.Attack.TechniqueID != "i" || !strings.HasPrefix(k.ID, "90-") {
		t.Fatalf("decoded %+v", k)
	}
}
