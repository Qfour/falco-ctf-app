package edition

// ADR-0056 V96 (A4e-5, amendment 18), the library's side: CheckInput and RenderEventInput take the
// scope as exactly one of a scenario path and AllChallenges, so an empty path is never "every
// challenge". The four combinations, through scopeArgsErr and through both validate methods.

import (
	"errors"
	"testing"
)

func TestScopeArgs_ExactlyOneOfScenarioAndAllChallenges(t *testing.T) {
	for _, c := range []struct {
		name     string
		scenario string
		all      bool
		ok       bool
	}{
		{"a scenario alone", "scenario.yaml", false, true},
		{"every challenge alone", "", true, true},
		{"neither (an empty scenario is not every challenge)", "", false, false},
		{"both", "scenario.yaml", true, false},
	} {
		err := scopeArgsErr(c.scenario, c.all)
		var ie *InputError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v, want no error", c.name, err)
		case !c.ok && !errors.As(err, &ie):
			t.Errorf("%s: %v, want an *InputError", c.name, err)
		}
		if c.ok {
			continue
		}
		// validate refuses it before anything else is looked at.
		if err := (CheckInput{ScenarioFile: c.scenario, AllChallenges: c.all}).validate(); !errors.As(err, &ie) {
			t.Errorf("CheckInput, %s: %v, want an *InputError", c.name, err)
		}
		if err := (RenderEventInput{ScenarioFile: c.scenario, AllChallenges: c.all}).validate(); !errors.As(err, &ie) {
			t.Errorf("RenderEventInput, %s: %v, want an *InputError", c.name, err)
		}
	}
}
