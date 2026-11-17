package edition_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// ADR-0056 D20 step 4 and amendment 14 (#656), fixed by reading the sources: the self check of
// `edition render`. Amendment 14 found that B7 (CheckDecoySpread) and T7 cannot be broken through
// the inputs the renderer takes, so no behavioural test turns red when the self check's call of
// one of them is taken out. The wiring is held here instead:
//
//   - in RenderEvent (internal/edition/eventrender.go), CheckDecoySpread and CheckOutputSpace are
//     each called once, as an argument of `X = append(X, ...)` (the result is a refusal, not
//     dropped), inside a `for _, cid := range ...` loop, with that cid as their first argument (once
//     per challenge);
//   - checkAnswersData is called once, as the Init of an `if _, _, _, e := checkAnswersData(...);
//     e != nil` whose body appends something made of e to the same X;
//   - after all three, and before the output is written (writeTreeAtomic), an `if e :=
//     errors.Join(X...); e != nil` returns e: the refusals stop the render.
//
// The practice edition (RenderPracticeEdition, internal/edition/practiceedition.go) has one self
// check of its own, the size of the answers table: an `if len(...) > MaxTableBytes` that returns
// an error, before replaceTreeAtomic. The rest of what its output is held to is not a self check
// of the command (B7 and B8 (b) are not a practice edition's rules, D10): the golden of V67, the
// practice mode's Load of the golden, and practiceedition_test.go's Parse and Check.

const (
	eventRenderPath   = "internal/edition/eventrender.go"
	practiceRenderPth = "internal/edition/practiceedition.go"
)

// funcBody is the body of the plain function name of the source at path p, or nil.
func funcBody(p, src, name string) (*ast.BlockStmt, error) {
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return nil, err
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name && fd.Body != nil {
			return fd.Body, nil
		}
	}
	return nil, nil
}

// identName is the name of e when it is an identifier, or "".
func identName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// calledName is the name of the function of a call: an identifier, or the last name of a
// selector.
func calledName(c *ast.CallExpr) string {
	switch fun := c.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// appendTarget is X when the statement is `X = append(X, ...)`, or "".
func appendTarget(n ast.Node) (string, *ast.CallExpr) {
	a, ok := n.(*ast.AssignStmt)
	if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
		return "", nil
	}
	x := identName(a.Lhs[0])
	c, ok := a.Rhs[0].(*ast.CallExpr)
	if x == "" || !ok || identName(c.Fun) != "append" || len(c.Args) < 2 || identName(c.Args[0]) != x {
		return "", nil
	}
	return x, c
}

// mentions reports whether name is an identifier somewhere in n.
func mentions(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if id, ok := m.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// selfCheckViolations judges the source of eventrender.go for the rule in the header.
func selfCheckViolations(src string) []string {
	body, err := funcBody(eventRenderPath, src, "RenderEvent")
	if err != nil {
		return []string{eventRenderPath + ": does not parse: " + err.Error()}
	}
	if body == nil {
		return []string{eventRenderPath + ": func RenderEvent is not found"}
	}
	var out []string
	calls := map[string]int{}
	var writePos token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			calls[calledName(c)]++
			if calledName(c) == "writeTreeAtomic" && writePos == token.NoPos {
				writePos = c.Pos()
			}
		}
		return true
	})
	for _, name := range []string{"CheckDecoySpread", "CheckOutputSpace", "checkAnswersData"} {
		if calls[name] != 1 {
			out = append(out, eventRenderPath+": RenderEvent calls "+name+" "+strconv.Itoa(calls[name])+" times, want once")
		}
	}
	if writePos == token.NoPos {
		out = append(out, eventRenderPath+": RenderEvent does not call writeTreeAtomic: the scan does not see the output")
	}

	// The two output checks: appended to the refusals, per challenge.
	targets := map[string]string{}
	last := token.NoPos
	ast.Inspect(body, func(n ast.Node) bool {
		r, ok := n.(*ast.RangeStmt)
		if !ok || (identName(r.Value) != "cid" && identName(r.Key) != "cid") {
			return true
		}
		ast.Inspect(r.Body, func(m ast.Node) bool {
			x, app := appendTarget(m)
			if app == nil {
				return true
			}
			for _, a := range app.Args[1:] {
				c, ok := a.(*ast.CallExpr)
				if !ok || len(c.Args) == 0 || identName(c.Args[0]) != "cid" {
					continue
				}
				if name := calledName(c); name == "CheckDecoySpread" || name == "CheckOutputSpace" {
					targets[name] = x
					if c.End() > last {
						last = c.End()
					}
				}
			}
			return true
		})
		return true
	})
	for _, name := range []string{"CheckDecoySpread", "CheckOutputSpace"} {
		if targets[name] == "" {
			out = append(out, eventRenderPath+": the result of "+name+"(cid, ...) is not appended to the refusals in a `for _, cid := range` loop of RenderEvent")
		}
	}

	// The answers table's check: its error appended to the same refusals.
	ast.Inspect(body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || s.Init == nil {
			return true
		}
		a, ok := s.Init.(*ast.AssignStmt)
		if !ok || len(a.Rhs) != 1 || len(a.Lhs) == 0 {
			return true
		}
		c, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || calledName(c) != "checkAnswersData" {
			return true
		}
		e := identName(a.Lhs[len(a.Lhs)-1])
		b, ok := s.Cond.(*ast.BinaryExpr)
		if e == "" || e == "_" || !ok || b.Op != token.NEQ || identName(b.X) != e || identName(b.Y) != "nil" {
			return true
		}
		for _, st := range s.Body.List {
			if x, app := appendTarget(st); app != nil && mentions(app, e) {
				targets["checkAnswersData"] = x
				if st.End() > last {
					last = st.End()
				}
			}
		}
		return true
	})
	if targets["checkAnswersData"] == "" {
		out = append(out, eventRenderPath+": the error of checkAnswersData is not tested and appended to the refusals in RenderEvent")
	}
	x := targets["CheckDecoySpread"]
	for name, t := range targets {
		if t != x {
			out = append(out, eventRenderPath+": the result of "+name+" is appended to "+t+", not to "+x+" with the others")
		}
	}
	if len(out) != 0 {
		return out
	}

	// The refusals stop the render: a Join of them, tested and returned, after the three and
	// before the output is written.
	joined := false
	ast.Inspect(body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || s.Init == nil || s.Pos() < last || s.End() > writePos {
			return true
		}
		a, ok := s.Init.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return true
		}
		c, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, isSel := c.Fun.(*ast.SelectorExpr)
		if !isSel || identName(sel.X) != "errors" || sel.Sel.Name != "Join" || len(c.Args) != 1 || identName(c.Args[0]) != x || c.Ellipsis == token.NoPos {
			return true
		}
		e := identName(a.Lhs[0])
		b, ok := s.Cond.(*ast.BinaryExpr)
		if !ok || b.Op != token.NEQ || identName(b.X) != e || identName(b.Y) != "nil" {
			return true
		}
		for _, st := range s.Body.List {
			if r, ok := st.(*ast.ReturnStmt); ok && len(r.Results) > 0 && identName(r.Results[len(r.Results)-1]) == e {
				joined = true
			}
		}
		return true
	})
	if !joined {
		out = append(out, eventRenderPath+": no `if e := errors.Join("+x+"...); e != nil { return ..., e }` comes after the self check and before writeTreeAtomic")
	}
	return out
}

// practiceSelfCheckViolations judges the source of practiceedition.go: RenderPracticeEdition
// returns an error when the answers table is larger than MaxTableBytes, before replaceTreeAtomic.
func practiceSelfCheckViolations(src string) []string {
	body, err := funcBody(practiceRenderPth, src, "RenderPracticeEdition")
	if err != nil {
		return []string{practiceRenderPth + ": does not parse: " + err.Error()}
	}
	if body == nil {
		return []string{practiceRenderPth + ": func RenderPracticeEdition is not found"}
	}
	var writePos token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && calledName(c) == "replaceTreeAtomic" && writePos == token.NoPos {
			writePos = c.Pos()
		}
		return true
	})
	if writePos == token.NoPos {
		return []string{practiceRenderPth + ": RenderPracticeEdition does not call replaceTreeAtomic: the scan does not see the output"}
	}
	checked := false
	ast.Inspect(body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok || s.Pos() > writePos {
			return true
		}
		b, ok := s.Cond.(*ast.BinaryExpr)
		if !ok || b.Op != token.GTR || identName(b.Y) != "MaxTableBytes" {
			return true
		}
		if c, ok := b.X.(*ast.CallExpr); !ok || identName(c.Fun) != "len" {
			return true
		}
		for _, st := range s.Body.List {
			if r, ok := st.(*ast.ReturnStmt); ok && len(r.Results) > 0 && identName(r.Results[len(r.Results)-1]) != "nil" {
				checked = true
			}
		}
		return true
	})
	if !checked {
		return []string{practiceRenderPth + ": RenderPracticeEdition does not refuse an answers table over MaxTableBytes before replaceTreeAtomic"}
	}
	return nil
}

func TestTheSelfCheckOfTheRenderIsWired(t *testing.T) {
	files := nonTestSources(t)
	src, ok := files[eventRenderPath]
	if !ok {
		t.Fatalf("%s is not there", eventRenderPath)
	}
	for _, v := range selfCheckViolations(src) {
		t.Error(v)
	}

	const (
		decoyCall = "CheckDecoySpread(cid, ed.spec, scope[cid], ed.template, bundles[cid])"
		decoyLine = "\t\t\t" + decoyCall + ",\n"
		spaceLine = "\t\t\tCheckOutputSpace(cid, scope[cid], bundles[cid]))\n"
		appendTo  = "\t\trefusals = append(refusals,\n"
		tableIf   = "} else if _, _, _, err := checkAnswersData(scored, table.Bytes(), true); err != nil {\n\t\trefusals = append(refusals, classify(\"the answers table of the render cannot be checked\", err))\n\t}"
		tableKeep = "refusals = append(refusals, classify(\"the answers table of the render cannot be checked\", err))"
		joinStep4 = "\tif err := errors.Join(refusals...); err != nil {\n\t\treturn nil, err\n\t}\n\tvar record bytes.Buffer"
	)
	for name, mutated := range map[string]string{
		"the call of CheckDecoySpread taken out":    replaceOnce(t, src, decoyLine, ""),
		"the call of CheckOutputSpace taken out":    replaceOnce(t, src, decoyLine+spaceLine, "\t\t\t"+decoyCall+")\n"),
		"the result of CheckDecoySpread dropped":    replaceOnce(t, src, appendTo+decoyLine, "\t\t_ = "+decoyCall+"\n"+appendTo),
		"the checks appended to another list":       replaceOnce(t, src, appendTo+decoyLine, "\t\tignored = append(ignored,\n"+decoyLine),
		"the answers table's check dropped":         replaceOnce(t, src, tableIf, "} else {\n\t\t_, _, _, _ = checkAnswersData(scored, table.Bytes(), true)\n\t}"),
		"the answers table's error not appended":    replaceOnce(t, src, tableKeep, "_ = err"),
		"the refusals of the self check not joined": replaceOnce(t, src, joinStep4, "\tvar record bytes.Buffer"),
	} {
		if v := selfCheckViolations(mutated); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
	if v := selfCheckViolations("package edition\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no RenderEvent was not reported (an extraction of nothing is not a pass)")
	}
}

func TestTheSelfCheckOfThePracticeRenderIsWired(t *testing.T) {
	files := nonTestSources(t)
	src, ok := files[practiceRenderPth]
	if !ok {
		t.Fatalf("%s is not there", practiceRenderPth)
	}
	for _, v := range practiceSelfCheckViolations(src) {
		t.Error(v)
	}
	const sizeCheck = "\tif len(pf.Answers) > MaxTableBytes {\n\t\treturn nil, newViolation(RuleShape, \"the answers table of the practice render is larger than the size limit\", 0, cell{cid: cid}, nil)\n\t}\n"
	for name, mutated := range map[string]string{
		"the size check taken out":        replaceOnce(t, src, sizeCheck, ""),
		"the size check returns no error": replaceOnce(t, src, sizeCheck, "\tif len(pf.Answers) > MaxTableBytes {\n\t\treturn nil, nil\n\t}\n"),
	} {
		if v := practiceSelfCheckViolations(mutated); len(v) == 0 {
			t.Errorf("%s: no violation was reported", name)
		}
	}
	if v := practiceSelfCheckViolations("package edition\n\nfunc other() {}\n"); len(v) == 0 {
		t.Error("a file with no RenderPracticeEdition was not reported")
	}
}
