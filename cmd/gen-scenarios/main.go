// Command gen-scenarios is the generator of ADR-0055 D5 (stage S2b-1). It writes each
// scenarios/<id>/scenario.yaml from that directory's module.yaml or course.yaml, read
// by internal/catalog's strict parser and flattened by catalog.Compose / ComposeSolo
// over the challenge pool challenges/ (catalog.Load): the code the runtime uses, not a
// second copy.
//
// Usage:
//
//	gen-scenarios [--check] [--allow-no-source] [--out <dir>] <repo-root>
//
// Without --check it writes <dir>/scenarios/<id>/scenario.yaml for every source (<dir>
// is --out, default <repo-root>). With --check it writes nothing and compares the bytes
// it would write with the scenario.yaml in <repo-root>.
//
// Exit status:
//
//	0  written; with --check, every generated scenario.yaml is up to date
//	1  --check: a scenario.yaml differs from what its source generates, is missing or is
//	   not a regular file, or is a generated file left in a directory with no source
//	   (each one is named on stderr)
//	2  usage
//	3  failed: a source is invalid, the pool or a file cannot be read, there is no source
//	   at all, or a file cannot be written
//
// All of it is generated in memory first, so an invalid source writes no file. A write
// failure stops at that file: the files written before it stay written.
//
// A directory of scenarios/ with neither module.yaml nor course.yaml is left alone in this
// stage: its hand-written scenario.yaml is neither rewritten nor removed (S2c refuses such
// a directory). --check fails on such a scenario.yaml when it starts with this generator's
// header: the source was removed and its output is left behind. No source at all is an
// error, since a wrong root must not read as "nothing to generate"; --allow-no-source
// accepts it, for the Makefile only until the tree is migrated (S2b-2; see
// Dockerfile.gen-scenarios).
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

const (
	exitOK    = 0
	exitStale = 1
	exitUsage = 2
	exitFail  = 3
)

const usage = "usage: gen-scenarios [--check] [--allow-no-source] [--out <dir>] <repo-root>"

// genFile is one generated scenario.yaml: rel is its slash path from the repo root, from
// the slash path of the source it is generated from.
type genFile struct {
	rel, from string
	data      []byte
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("gen-scenarios", flag.ContinueOnError)
	fl.SetOutput(stderr)
	check := fl.Bool("check", false, "compare with the scenario.yaml files in <repo-root>; write nothing")
	allowNone := fl.Bool("allow-no-source", false, "accept a tree with no module.yaml or course.yaml")
	out := fl.String("out", "", "write under this directory instead of <repo-root>")
	if err := fl.Parse(args); err != nil {
		return exitUsage
	}
	if fl.NArg() != 1 || (*check && *out != "") {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	root := fl.Arg(0)
	files, unsourced, err := generate(root)
	if err != nil {
		fmt.Fprintf(stderr, "gen-scenarios: %v\n", err)
		return exitFail
	}
	if len(files) == 0 && !*allowNone {
		fmt.Fprintf(stderr, "gen-scenarios: no %s or %s under %s (a wrong root is not \"nothing to generate\")\n",
			catalog.ModuleFile, catalog.CourseFile, filepath.Join(root, "scenarios"))
		return exitFail
	}
	if *check {
		return checkFiles(root, files, unsourced, stdout, stderr)
	}
	if len(files) == 0 {
		fmt.Fprintln(stdout, "gen-scenarios: no source yet (--allow-no-source): nothing generated")
		return exitOK
	}
	dest := root
	if *out != "" {
		dest = *out
	}
	for _, f := range files {
		if err := writeAtomic(filepath.Join(dest, filepath.FromSlash(f.rel)), f.data); err != nil {
			fmt.Fprintf(stderr, "gen-scenarios: %v\n", err)
			return exitFail
		}
		fmt.Fprintf(stdout, "gen-scenarios: wrote %s\n", f.rel)
	}
	return exitOK
}

// generate composes every source under <root>/scenarios, in directory-name order. unsourced
// is the slash path of scenario.yaml in each directory that has no source.
func generate(root string) (files []genFile, unsourced []string, err error) {
	cat, err := catalog.Load(filepath.Join(root, "challenges"))
	if err != nil {
		return nil, nil, err
	}
	scen := filepath.Join(root, "scenarios")
	entries, err := os.ReadDir(scen) // sorted by name
	if err != nil {
		return nil, nil, fmt.Errorf("list %s: %w", scen, err)
	}
	var sources []catalog.Source
	modules := make(map[string]catalog.Module)
	for _, e := range entries {
		dir := filepath.Join(scen, e.Name())
		if e.Type()&fs.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%s is a symlink: a scenario directory must be a directory", dir)
		}
		if !e.IsDir() {
			continue // scenarios/README.md
		}
		has, err := hasSource(dir)
		if err != nil {
			return nil, nil, err
		}
		if !has {
			// S2b-1: a directory without a source is left alone (--check looks at it).
			unsourced = append(unsourced, path.Join("scenarios", e.Name(), "scenario.yaml"))
			continue
		}
		src, err := catalog.LoadSource(dir)
		if err != nil {
			return nil, nil, err
		}
		if src.Module != nil {
			modules[src.Module.ID] = *src.Module
		}
		sources = append(sources, src)
	}
	files = make([]genFile, 0, len(sources))
	for _, src := range sources {
		var c catalog.Composed
		from := catalog.CourseFile
		if src.Module != nil {
			from = catalog.ModuleFile
			c, err = catalog.ComposeSolo(*src.Module, cat)
		} else {
			c, err = catalog.Compose(*src.Course, modules, cat)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", src.Dir, err)
		}
		f := genFile{rel: path.Join("scenarios", c.ID, "scenario.yaml"), from: path.Join("scenarios", c.ID, from)}
		if f.data, err = render(c, f.from); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f.rel, err)
		}
		files = append(files, f)
	}
	return files, unsourced, nil
}

// hasSource reports whether dir holds a module.yaml or a course.yaml entry of any kind
// (catalog.LoadSource then refuses a symlink, a directory, or both files).
func hasSource(dir string) (bool, error) {
	for _, name := range []string{catalog.ModuleFile, catalog.CourseFile} {
		_, err := os.Lstat(filepath.Join(dir, name))
		switch {
		case err == nil:
			return true, nil
		case !errors.Is(err, fs.ErrNotExist):
			return false, fmt.Errorf("stat %s: %w", filepath.Join(dir, name), err)
		}
	}
	return false, nil
}

// checkFiles compares each generated file with the one in root, byte for byte, and fails
// on an unsourced scenario.yaml that starts with this generator's header (its source was
// removed; a hand-written one passes).
func checkFiles(root string, files []genFile, unsourced []string, stdout, stderr io.Writer) int {
	stale := 0
	for _, rel := range unsourced {
		p := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
			continue // S2b-1 leaves these directories alone; S2c refuses them
		}
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "gen-scenarios: read %s: %v\n", p, err)
			return exitFail
		}
		if bytes.HasPrefix(data, []byte(headerPrefix)) {
			fmt.Fprintf(stderr, "gen-scenarios: %s was generated, but its directory has no %s or %s: the source was removed and its output left behind\n",
				rel, catalog.ModuleFile, catalog.CourseFile)
			stale++
		}
	}
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f.rel))
		info, err := os.Lstat(p)
		var have []byte
		if err == nil && info.Mode().IsRegular() {
			have, err = os.ReadFile(p)
		}
		switch {
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(stderr, "gen-scenarios: %s is missing: run make gen-scenarios\n", f.rel)
			stale++
		case err != nil:
			fmt.Fprintf(stderr, "gen-scenarios: read %s: %v\n", p, err)
			return exitFail
		case !info.Mode().IsRegular():
			fmt.Fprintf(stderr, "gen-scenarios: %s is not a regular file: run make gen-scenarios\n", f.rel)
			stale++
		case !bytes.Equal(have, f.data):
			fmt.Fprintf(stderr, "gen-scenarios: %s differs from what %s generates: edit the source, not this file, and run make gen-scenarios\n", f.rel, f.from)
			stale++
		}
	}
	if stale > 0 {
		fmt.Fprintf(stderr, "gen-scenarios: %d scenario.yaml out of date\n", stale)
		return exitStale
	}
	fmt.Fprintf(stdout, "gen-scenarios: %d scenario.yaml up to date\n", len(files))
	return exitOK
}

// writeAtomic writes data to p through a temporary file in the same directory and a
// rename, so p is never left half written (a symlink at p is replaced, not followed).
func writeAtomic(p string, data []byte) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".scenario.yaml.tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	err = errors.Join(werr, cerr)
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		_ = os.Remove(tmp.Name()) // best effort: the write already failed and is reported
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}
