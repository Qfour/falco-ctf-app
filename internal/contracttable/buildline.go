package contracttable

// ADR-0054: the form of the Makefile's `docker build` lines and the rule for their
// `-f` / context paths are a cross-repo contract. platform's release
// (scripts/release-images.sh -> scripts/lib/release-scan.sh, rs_build_args_checked)
// reads ONE line per image out of the Makefile and hands only <Dockerfile> and
// <context> to its own `docker build --no-cache --platform ...`, so a Makefile that
// breaks the form must be red here, in the PR, and not at release time.
//
// Everything in this file is a judgement on STRINGS. What a file system adds
// (tracked, regular file, no symlink element) is checked by the tests, with
// fixtures. The judgements mirror platform's shell one for one, and the shared
// case table (testdata/build-path-cases.tsv) pins the path rules for both sides;
// lines 1-2 of the table carry pathGrammar / buildLine as literals for other repos
// (ADR-0054 D3).

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// BuildArgs is what platform's release takes from one build line: the `-f` value
// and the context. The `-t` value and anything else on the line never reach it.
type BuildArgs struct {
	Dockerfile string
	Context    string
}

// buildLineCandidate is what platform treats as "a build line" before it looks at
// the form: a `docker build` (an optional make recipe prefix `@` `+` `-` is part of
// the match) that names $(REGISTRY). Every line that matches buildLine is a
// candidate (the form is a subset of the candidates), so it is never skipped. A
// line that is not a candidate (`${REGISTRY}`, `@ docker` with a space after the
// prefix, `$(DOCKER) build`, ...) is read by neither this function nor platform and
// hands nothing to the release's build. `docker buildx build` is a candidate and is
// outside the form, so it is an error.
var buildLineCandidate = regexp.MustCompile(`^[[:space:]]*[@+-]*docker[[:space:]]+build`)

// buildLine is the one accepted form (platform's RS_BUILD_LINE_RE): leading
// whitespace (the recipe TAB), single spaces between `docker`, `build`, `-t` and the
// tag, one or more whitespace characters before `-f`, after `-f` and between the two
// paths, and nothing after the context (no argument, no trailing whitespace, no
// continuation, no carriage return).
var buildLine = regexp.MustCompile(`^[[:space:]]+docker build -t \$\(REGISTRY\)/([a-z0-9][a-z0-9-]*):\$\(TAG\)[[:space:]]+-f[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)$`)

// MakefileBuildLines returns, per image of the `IMAGES :=` line (read by
// MakefileImages, so there is one reader of that line), the -f / context pair of its
// build line. The result is an error, never a best-effort map, when the IMAGES line
// itself is not readable (MakefileImages), when a candidate line is not in the
// accepted form or ends in a backslash, when a line is for an image that IMAGES does
// not name, when an image has two lines (platform must not silently read the first),
// and when an image of IMAGES has no line. The paths are returned as written;
// CheckBuildPaths judges them.
func MakefileBuildLines(makefile string) (map[string]BuildArgs, error) {
	images, err := MakefileImages(makefile)
	if err != nil {
		return nil, fmt.Errorf("IMAGES: %w", err)
	}
	got := map[string]BuildArgs{}
	for i, ln := range strings.Split(makefile, "\n") {
		if !buildLineCandidate.MatchString(ln) || !strings.Contains(ln, "$(REGISTRY)") {
			continue
		}
		m := buildLine.FindStringSubmatch(ln)
		if m == nil || strings.HasSuffix(ln, `\`) {
			return nil, fmt.Errorf("Makefile line %d is not in the form platform reads (<whitespace>docker build -t $(REGISTRY)/<name>:$(TAG) -f <Dockerfile> <context>, nothing else): %q", i+1, ln)
		}
		name := m[1]
		if !slices.Contains(images, name) {
			return nil, fmt.Errorf("Makefile line %d builds %q, which IMAGES does not name: %q", i+1, name, ln)
		}
		if _, dup := got[name]; dup {
			return nil, fmt.Errorf("Makefile line %d is a second build line for %q (platform must read exactly one): %q", i+1, name, ln)
		}
		got[name] = BuildArgs{Dockerfile: m[2], Context: m[3]}
	}
	for _, name := range images {
		if _, ok := got[name]; !ok {
			return nil, fmt.Errorf("IMAGES names %q but the Makefile has no build line for it", name)
		}
	}
	if len(got) == 0 {
		return nil, fmt.Errorf("no build line read (an empty set is not a pass)")
	}
	return got, nil
}

// pathGrammar is the character set and the first character of a path (platform's
// RS_PATH_RE): no leading `/`, `$`, `~`, `-`, no whitespace, no quote.
var pathGrammar = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]*$`)

// hasElement reports whether path, split on `/`, has an element equal to elem
// ("" is the empty element of `//` and of a leading or trailing `/`).
func hasElement(path, elem string) bool {
	return slices.Contains(strings.Split(path, "/"), elem)
}

// pathRule is one named rule of the path judgement. The judgement is the whole
// list, in order; the tests drop one rule at a time to show that each rule decides
// at least one row of the shared case table (a rule nothing needs is a rule nobody
// notices missing).
type pathRule struct {
	name  string
	holds func(dockerfile, context string) bool
}

// pathRules is the judgement of D2 on strings, the same as platform's
// rs_build_path_ok. The rules are independent: each one has a row of the shared
// table that only it rejects.
var pathRules = []pathRule{
	{"grammar", func(dockerfile, context string) bool {
		return pathGrammar.MatchString(dockerfile) && pathGrammar.MatchString(context)
	}},
	{"no-dotdot-element", func(dockerfile, context string) bool {
		return !hasElement(dockerfile, "..") && !hasElement(context, "..")
	}},
	// The element `.` is allowed only as the whole context (`-f x/Dockerfile .`).
	{"no-dot-element", func(dockerfile, context string) bool {
		return !hasElement(dockerfile, ".") && (context == "." || !hasElement(context, "."))
	}},
	{"no-empty-element", func(dockerfile, context string) bool {
		return !hasElement(dockerfile, "") && !hasElement(context, "")
	}},
	// Inside is a prefix of the canonical string, with the `/` included: context
	// `images/ttyd` does not contain `images/ttyd-proxy/Dockerfile`.
	{"dockerfile-inside-context", func(dockerfile, context string) bool {
		return context == "." || strings.HasPrefix(dockerfile, context+"/")
	}},
}

// CheckBuildPaths judges a build line's two paths by D2's string rules: nil when
// every rule holds, else an error naming the first rule that does not.
func CheckBuildPaths(dockerfile, context string) error {
	return checkBuildPaths("", dockerfile, context)
}

// checkBuildPaths is CheckBuildPaths with the rule named skip left out ("" leaves
// none out). The production judgement is skip == "": a skipped rule exists only so
// that a test can show what the rule was holding up.
func checkBuildPaths(skip, dockerfile, context string) error {
	for _, r := range pathRules {
		if r.name == skip {
			continue
		}
		if !r.holds(dockerfile, context) {
			return fmt.Errorf("rule %q: -f %q with context %q", r.name, dockerfile, context)
		}
	}
	return nil
}
