package edition_test

import (
	"strings"
	"testing"
)

// ADR-0056 D10 B7 / B8 (b), D19 A4d-2c, fixed by reading the sources (the way
// render_reach_test.go fixes the renderer): the output half of B7 and B8 (b) is spread.go, and it
// is NOT a render file. It holds neither the key nor an answer, and the validator does not trust
// the renderer, so it must not be able to reach the renderer's door either:
//
//   - spread.go is not named render*.go, so render_reach_test.go does not count it as a file of
//     the renderer, and TestRenderIsNotReachableFromTheScoreboard holds it to the rule of a file
//     outside the renderer: it refers to no exported name a render file declares (MasterKey,
//     Render, RenderInput, ...) and calls no unexported function a render file declares (the
//     random source, the template fill). This test adds that the file is there and is not a
//     render file, and that the scan would see a reach from it.
//   - who may call CheckDecoySpread and CheckOutputSpace is not fixed here: ADR-0056 asks for
//     no such pin (the `edition check` of A4e calls them, and they hold no secret). A4e adds
//     its caller, and the ADR's pin for that stage is the one of `edition render` in
//     render_reach_test.go.

const spreadPath = "internal/edition/spread.go"

func TestSpreadIsNotARenderFileAndDoesNotReachTheRenderer(t *testing.T) {
	files := nonTestSources(t)
	src, ok := files[spreadPath]
	if !ok {
		t.Fatalf("%s is not there", spreadPath)
	}
	if isRenderFile(spreadPath) {
		t.Errorf("%s is counted as a file of the renderer: B7 and B8 (b) hold no key and no answer, and must not be named render*.go", spreadPath)
	}
	exported, unexported := renderDeclarations(t, files)
	for _, name := range []string{"CheckDecoySpread", "CheckOutputSpace", "SpreadSeat", "RuleDecoySpread", "CandidateFactor"} {
		if exported[name] {
			t.Errorf("a render file declares %s, which is B7 / B8 (b)'s", name)
		}
	}
	for _, name := range []string{"prepareSpread", "templateLayout", "fitsFormat", "fileTokens"} {
		if unexported[name] {
			t.Errorf("a render file declares %s, which spread.go declares", name)
		}
	}
	// The scan covers the file: nothing in spread.go reaches the renderer.
	for _, v := range renderReaches(t, files, nil) {
		if strings.HasPrefix(v, spreadPath) {
			t.Error(v)
		}
	}

	// The scan itself: a copy of spread.go with one reach into the renderer is reported (a
	// reach is reported for a file that is not a render file whatever it is called).
	base := map[string]string{
		"internal/edition/render.go": "package edition\n\nfunc Render() {}\n\nfunc render() {}\n\ntype MasterKey struct{}\n",
		spreadPath:                   src,
	}
	if v := renderReaches(t, base, nil); len(v) != 0 {
		t.Fatalf("the real spread.go reaches the renderer: %v", v)
	}
	for name, add := range map[string]string{
		"the key":              "\nvar planted MasterKey\n",
		"a call of Render":     "\nfunc planted() { Render() }\n",
		"a call of the render": "\nfunc planted2() { render() }\n",
	} {
		files := rdCopyFiles(base)
		files[spreadPath] = src + add
		if v := renderReaches(t, files, nil); len(v) == 0 {
			t.Errorf("%s: a reach from spread.go was not reported", name)
		}
	}
}
