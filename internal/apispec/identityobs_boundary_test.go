package apispec

// ADR-0038 V7 (app#404): internal/scoreboard/identityobs is the scoreboard's
// observation point for identity refusals, and the collector must not link it.
// The collector links internal/scoreboard/ratelimit and COPYs it by name into
// its image (collector/Dockerfile), and `build (collector)` is not a required
// check. So an import of identityobs from ratelimit (or anything else the
// collector links) would compile on the host and in `make test`, stay green in
// CI, and break only the collector image — or, if the Dockerfile were widened to
// fix it, put the scoreboard's metric into the collector's /metrics.
// ratelimit therefore takes a func from its caller (ratelimit.NoIdentityObserver)
// instead of importing identityobs. The Go compiler already forbids the reverse
// pair of imports (identityobs imports ratelimit for the header name); this
// test is the check that the closure itself stays free of it, and that every
// package the collector does link is one its Dockerfile COPYs.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const identityobsImportPath = modulePrefix + "internal/scoreboard/identityobs"

func TestNoDistrolessBinaryLinksIdentityobs(t *testing.T) {
	root := repoRoot(t)
	for _, cmd := range []string{"collector", "auth-policy"} {
		t.Run(cmd, func(t *testing.T) {
			closure := transitiveModuleImports(t, root, modulePrefix+"cmd/"+cmd)
			if len(closure) < 3 {
				t.Fatalf("cmd/%s's closure = %v: the walk is broken, not clean", cmd, closure)
			}
			if closure[identityobsImportPath] {
				t.Fatalf("cmd/%s's module-internal import closure includes %s: the scoreboard-only observation point must not be linked into this image (ADR-0038 D3, V7); hand the package a func instead of importing it", cmd, identityobsImportPath)
			}
		})
	}
}

// The check is not vacuous: a two-hop chain from a binary through a package it
// already links (ratelimit) to identityobs is found.
func TestNoDistrolessBinaryLinksIdentityobs_CatchesTransitiveImport(t *testing.T) {
	root := t.TempDir()
	mustWriteGoFile(t, filepath.Join(root, "cmd", "fakebin"), "main.go",
		`package main

import _ "`+modulePrefix+`internal/scoreboard/ratelimit"

func main() {}
`)
	mustWriteGoFile(t, filepath.Join(root, "internal", "scoreboard", "ratelimit"), "r.go",
		`package ratelimit

import _ "`+identityobsImportPath+`"
`)
	closure := transitiveModuleImports(t, root, modulePrefix+"cmd/fakebin")
	if !closure[identityobsImportPath] {
		t.Fatalf("the synthetic cmd/fakebin -> ratelimit -> identityobs chain was not found: %v", closure)
	}
}

// copiedDirs returns the source of every `COPY <src> <dst>` line of a
// Dockerfile (flags like --from= skipped; a trailing slash trimmed).
func copiedDirs(dockerfile string) map[string]bool {
	out := map[string]bool{}
	for _, ln := range strings.Split(dockerfile, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 || strings.ToUpper(f[0]) != "COPY" {
			continue
		}
		var args []string
		for _, a := range f[1:] {
			if !strings.HasPrefix(a, "--") {
				args = append(args, a)
			}
		}
		if len(args) >= 2 {
			out[strings.TrimSuffix(args[0], "/")] = true
		}
	}
	return out
}

// uncopiedPackages lists the module-internal packages of closure (other than
// internal/apispec, whose file set ADR-0037 V4 owns, and the cmd package itself,
// which is COPYed by its own line) that dockerfile does not COPY by directory.
func uncopiedPackages(dockerfile string, closure map[string]bool) []string {
	copied := copiedDirs(dockerfile)
	var missing []string
	for pkg := range closure {
		dir := strings.TrimPrefix(pkg, modulePrefix)
		if strings.HasPrefix(dir, "internal/apispec") {
			continue
		}
		if !copied[dir] {
			missing = append(missing, dir)
		}
	}
	return missing
}

// Every module-internal package the collector links is COPYed by directory in
// collector/Dockerfile: the other half of "nothing here builds on the host only".
func TestCollectorDockerfileCopiesItsWholeClosure(t *testing.T) {
	root := repoRoot(t)
	closure := transitiveModuleImports(t, root, modulePrefix+"cmd/collector")
	b, err := os.ReadFile(filepath.Join(root, "collector", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	df := string(b)
	if len(copiedDirs(df)) < 5 {
		t.Fatalf("parsed COPY sources %v from collector/Dockerfile: the parse is broken", copiedDirs(df))
	}
	if missing := uncopiedPackages(df, closure); len(missing) > 0 {
		t.Fatalf("collector/Dockerfile does not COPY %v, which cmd/collector links: the image build breaks while the host build is green", missing)
	}
	// Not vacuous: dropping ratelimit's COPY line is reported.
	broken := strings.ReplaceAll(df, "COPY internal/scoreboard/ratelimit ./internal/scoreboard/ratelimit", "")
	if broken == df {
		t.Fatal("the mutation (dropping ratelimit's COPY) changed nothing: the Dockerfile's line moved")
	}
	if missing := uncopiedPackages(broken, closure); len(missing) != 1 || missing[0] != "internal/scoreboard/ratelimit" {
		t.Fatalf("with ratelimit's COPY dropped the check reported %v, want [internal/scoreboard/ratelimit]", missing)
	}
}
