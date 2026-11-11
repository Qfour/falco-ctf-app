// Package contracttable reads the cross-repo contract table of
// .claude/rules/falco-ctf-app-conventions.md for TESTS: the table's rows are an
// agreement point with platform (app#486, app#482), and more than one test reads
// them. It is the one place that knows where the table is (the "Cross-repo 契約"
// section) and what a row is (a line starting with "|"), so two tests cannot scope
// a row lookup differently. Standard library only, and no production binary imports
// it (it holds no runtime behaviour; internal/apispec's closure checks would
// show it).
package contracttable

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

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

// MakefilePath is the Makefile, relative to the repository root. It is in the
// build context of Dockerfile.test (COPY . .; .dockerignore does not exclude it).
const MakefilePath = "Makefile"

// imagesDef matches any definition of IMAGES at the start of a line (:=, =, ?=,
// +=), so a second or differently-spelled definition is counted, not skipped.
var imagesDef = regexp.MustCompile(`^IMAGES[ \t]*[:?+]*=`)

// imageWord is one image name: a lower-case word, no make variable or function.
var imageWord = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// MakefileImages returns the image names of the Makefile's `IMAGES :=` line: the
// release image set that platform's release scan gate reads (scripts/lib/
// release-scan.sh; ADR-WS-0010 D8). platform reads ONE line, so the line is held
// to the form that reader understands, and anything else is an error here (never
// a best-effort set): exactly one definition, spelled `IMAGES :=`, no `\`
// continuation, no `#` comment on the line, at least one name and every name a
// plain word.
func MakefileImages(makefile string) ([]string, error) {
	var defs []string
	for _, ln := range strings.Split(makefile, "\n") {
		if imagesDef.MatchString(ln) {
			defs = append(defs, ln)
		}
	}
	switch len(defs) {
	case 0:
		return nil, errors.New("no IMAGES definition at the start of a line")
	case 1:
	default:
		return nil, fmt.Errorf("%d IMAGES definitions, want exactly 1: %q", len(defs), defs)
	}
	def := defs[0]
	rest := strings.TrimLeft(strings.TrimPrefix(def, "IMAGES"), " \t")
	body, ok := strings.CutPrefix(rest, ":=")
	if !ok {
		return nil, fmt.Errorf("IMAGES must be defined with `:=` (platform reads that form): %q", def)
	}
	if strings.HasSuffix(strings.TrimRight(body, " \t\r"), `\`) {
		return nil, fmt.Errorf("IMAGES line continues onto the next line (platform reads one line): %q", def)
	}
	if strings.Contains(body, "#") {
		return nil, fmt.Errorf("IMAGES line has a `#` (a trailing comment is not part of the set): %q", def)
	}
	names := strings.Fields(body)
	if len(names) == 0 {
		return nil, fmt.Errorf("IMAGES line names no image: %q", def)
	}
	for _, n := range names {
		if !imageWord.MatchString(n) {
			return nil, fmt.Errorf("IMAGES has %q, which is not a plain image name: %q", n, def)
		}
	}
	return names, nil
}
