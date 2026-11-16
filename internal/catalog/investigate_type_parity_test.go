package catalog

// ADR-0056 A5a-1: challenges/gen-values.sh decides which challenges are
// investigate challenges by matching the `type:` line against its own literal,
// INVESTIGATE_TYPE. The catalog's spelling is TypeInvestigate (a provisional
// name, ADR-0056 D1). If the constant is renamed here and the literal is not,
// every real investigate challenge silently drops out of the script's mountDir
// rules (sensitive directories, overlap). This test reads the script as text and
// holds the literal equal to the constant.
//
// Same style as mountroots_parity_test.go: an extraction that finds nothing, or
// finds the assignment twice, is a failure, never "equal".

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// a top-level assignment, single or double quoted: INVESTIGATE_TYPE='investigate'
var investigateTypeAssignRE = regexp.MustCompile(`(?m)^INVESTIGATE_TYPE=(?:'([^']*)'|"([^"]*)")[ \t]*(?:#.*)?$`)

// checkInvestigateType is the whole rule: the script assigns INVESTIGATE_TYPE
// exactly once, and the value is want.
func checkInvestigateType(src, want string) error {
	ms := investigateTypeAssignRE.FindAllStringSubmatch(src, -1)
	switch len(ms) {
	case 0:
		return fmt.Errorf("no top-level INVESTIGATE_TYPE='...' assignment was found: the extraction is broken or the script moved")
	case 1:
	default:
		return fmt.Errorf("INVESTIGATE_TYPE is assigned %d times: which one is the value is ambiguous", len(ms))
	}
	got := ms[0][1]
	if got == "" {
		got = ms[0][2]
	}
	if got != want {
		return fmt.Errorf("gen-values.sh INVESTIGATE_TYPE = %q, the catalog's TypeInvestigate is %q: investigate challenges would drop out of the script's mountDir rules", got, want)
	}
	return nil
}

func TestInvestigateType_GenValuesLiteralMatchesTheCatalog(t *testing.T) {
	raw, err := os.ReadFile(genValuesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkInvestigateType(string(raw), TypeInvestigate); err != nil {
		t.Error(err)
	}
}

// The check itself must be able to fail: a copy with the literal changed is red, an
// extraction that finds nothing is red, and so is a second assignment.
func TestInvestigateType_ParityCheckFailsOnADriftedCopy(t *testing.T) {
	raw, err := os.ReadFile(genValuesPath)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	old := "INVESTIGATE_TYPE='" + TypeInvestigate + "'"
	if strings.Count(src, old) != 1 {
		t.Fatalf("the negative test's text %q must occur exactly once in gen-values.sh (rewording the assignment makes this check vacuous: update it)", old)
	}
	if err := checkInvestigateType(strings.Replace(src, old, "INVESTIGATE_TYPE='inspect'", 1), TypeInvestigate); err == nil {
		t.Error("a renamed literal was not detected")
	}
	if err := checkInvestigateType(strings.Replace(src, old, `INVESTIGATE_TYPE="`+TypeInvestigate+`"`, 1), TypeInvestigate); err != nil {
		t.Errorf("the same value in double quotes: %v", err)
	}
	if err := checkInvestigateType(strings.Replace(src, old, "  "+old, 1), TypeInvestigate); err == nil {
		t.Error("an assignment no longer at the top level was accepted: an empty extraction must fail")
	}
	if err := checkInvestigateType(src+"\nINVESTIGATE_TYPE='other'\n", TypeInvestigate); err == nil {
		t.Error("a second assignment was accepted")
	}
	if err := checkInvestigateType(src, TypeInvestigate+"-renamed"); err == nil {
		t.Error("the Go constant drifting from the literal was not detected")
	}
	for name, s := range map[string]string{"empty": "", "no assignment": "echo INVESTIGATE_TYPE\n"} {
		if err := checkInvestigateType(s, TypeInvestigate); err == nil {
			t.Errorf("%s source was accepted: an empty extraction must fail", name)
		}
	}
}
