// Package contracttable reads the cross-repo contract table of
// .claude/rules/falco-ctf-app-conventions.md for TESTS: the table's rows are an
// agreement point with platform (app#486, app#482), and more than one test reads
// them. It is the one place that knows where the table is (the "Cross-repo 契約"
// section) and what a row is (a line starting with "|"), so two tests cannot scope
// a row lookup differently. Standard library only, and no production binary imports
// it (it holds no runtime behaviour; internal/apispec's closure checks would
// show it).
package contracttable

import "strings"

// Path is the conventions file, relative to the repository root. The build context
// of Dockerfile.test receives it through an exception in .dockerignore.
const Path = ".claude/rules/falco-ctf-app-conventions.md"

// Heading starts the section holding the table.
const Heading = "\n## Cross-repo 契約"

// Rows returns the table rows (lines starting with "|") of the section of doc that
// starts at Heading and ends at the next "## " heading; nil when there is no such
// section.
func Rows(doc string) []string {
	_, after, ok := strings.Cut(doc, Heading)
	if !ok {
		return nil
	}
	section, _, _ := strings.Cut(after, "\n## ")
	var out []string
	for _, ln := range strings.Split(section, "\n") {
		if strings.HasPrefix(ln, "|") {
			out = append(out, ln)
		}
	}
	return out
}

// RowWhere returns the first row of the section for which match is true, or "".
func RowWhere(doc string, match func(row string) bool) string {
	for _, ln := range Rows(doc) {
		if match(ln) {
			return ln
		}
	}
	return ""
}
