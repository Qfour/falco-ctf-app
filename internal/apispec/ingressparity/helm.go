package ingressparity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// repoRoot locates the module root by walking up from THIS SOURCE FILE's
// own directory (via runtime.Caller, not os.Getwd) until a go.mod is found —
// the same technique internal/apispec/mux_ownership_test.go's repoRoot(t)
// helper uses, adapted to a plain error return since this is production
// (non-_test.go) code with no *testing.T to hand. Using the compiled-in
// source path rather than the process's working directory means
// LoadIngressEntries behaves identically no matter which package's test
// binary calls it (Go test binaries run with their OWN package directory as
// CWD, which would otherwise make this function's relative-path behaviour
// depend on which package imports it).
func repoRoot() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) failed — cannot locate ingressparity's own source file")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate go.mod walking up from %s", thisFile)
		}
		dir = parent
	}
}

// renderedIngress is the minimal shape this package reads out of `helm
// template`'s rendered charts/scoreboard/templates/ingress-journey.yaml —
// only spec.rules[].http.paths[].{path,pathType}, nothing else in the
// document (labels, annotations, tls, tls.hosts, ...) is relevant to I15.
type renderedIngress struct {
	Spec struct {
		Rules []struct {
			HTTP struct {
				Paths []struct {
					Path     string `yaml:"path"`
					PathType string `yaml:"pathType"`
				} `yaml:"paths"`
			} `yaml:"http"`
		} `yaml:"rules"`
	} `yaml:"spec"`
}

// LoadIngressEntries runs `helm template charts/scoreboard --show-only
// templates/ingress-journey.yaml` with the given journeyHost (ADR-0021 V1)
// and returns the rendered spec.rules[].http.paths[] entries.
//
// journeyHost is passed straight through to `--set ingress.journeyHost=`.
// The chart's ingress-journey.yaml template guards its entire body on
// `{{- if and .Values.ingress.enabled .Values.ingress.journeyHost }}`, and
// .Values.ingress.journeyHost's chart default is "" (empty string, falsy in
// Helm's text/template) — ADR-0021 C4's "journeyHost 空出力の罠". With
// journeyHost=="" the guarded template body renders to nothing at all, and
// `helm template --show-only templates/ingress-journey.yaml` (this
// function's exact invocation) errors out ("could not find template
// templates/ingress-journey.yaml in chart") rather than succeeding with an
// empty document — measured directly, not assumed from the chart source.
// That is actually a STRONGER fail-closed signal than ADR-0021 C4's
// "silently returns 0 entries" framing anticipated: this function
// propagates that error rather than swallowing it into an empty slice, so
// a caller who forgets `--set ingress.journeyHost=<non-empty>` gets a hard
// error from THIS call, not a green "0 uncovered" from a caller-side
// non-empty check running against silently-empty input. V(I15)-4's
// non-empty assert therefore matters most as a guard against a NON-empty
// but wrong result (e.g. `--show-only` pointed at the wrong template path)
// — see TestLoadIngressEntries_EmptyJourneyHostRendersNothing (helm_test.go)
// for the measured behaviour this comment describes.
//
// Requires `helm` on PATH and charts/scoreboard's local
// file://../falco-ctf-common chart dependency already resolved (`helm
// dependency build charts/scoreboard` — Dockerfile.test runs this once at
// image-build time, matching charts/scoreboard's Chart.yaml `dependencies:`
// pin; see that Dockerfile's own comment for why).
func LoadIngressEntries(journeyHost string) ([]IngressEntry, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("helm", "template", "charts/scoreboard",
		"--show-only", "templates/ingress-journey.yaml",
		"--set", "ingress.enabled=true",
		"--set", "ingress.journeyHost="+journeyHost,
	)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("helm template charts/scoreboard: %w (stderr: %s)", err, ee.Stderr)
		}
		return nil, fmt.Errorf("helm template charts/scoreboard: %w", err)
	}
	return parseIngressEntries(out)
}

// parseIngressEntries YAML-decodes `helm template`'s stdout (a single
// Ingress document, possibly preceded by a "# Source: ..." comment line and
// a leading "---" — both of which yaml.v3 skips as normal YAML syntax) into
// the flat []IngressEntry shape covers()/CoverageDiff() consume. An empty
// or non-matching document (e.g. the ingress.enabled/journeyHost guard
// suppressed all output) decodes to a zero-value renderedIngress and
// therefore an empty, non-nil-vs-nil-irrelevant slice — see
// LoadIngressEntries' doc for why that is a legitimate, caller-checked
// outcome rather than an error here.
//
// review-5x R2-F4 (LOW): a plain single-shot yaml.Unmarshal only ever reads
// the FIRST "---"-separated document in a stream and silently drops
// anything after it — if `--show-only templates/ingress-journey.yaml` ever
// matched more than one rendered document (a future chart change turning
// this template into a multi-object manifest, or a `--show-only` glob
// behaviour change upstream), any paths[] entries living in a SECOND
// document would vanish here with no error, exactly the "extraction quietly
// drops data" failure mode this package's whole design (D4, ADR-0021 C4)
// exists to avoid. This decodes every document in the stream with
// yaml.Decoder and FAILS if more than one is present, rather than silently
// keeping only the first.
func parseIngressEntries(doc []byte) ([]IngressEntry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	var docs []renderedIngress
	for {
		var ri renderedIngress
		if err := dec.Decode(&ri); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parse rendered ingress-journey.yaml (document %d): %w", len(docs)+1, err)
		}
		docs = append(docs, ri)
	}
	if len(docs) > 1 {
		return nil, fmt.Errorf("helm template --show-only templates/ingress-journey.yaml rendered %d YAML documents, want at most 1 — this package only reads the first document's spec.rules[].http.paths[], so a second document's entries would silently vanish; parseIngressEntries needs updating if ingress-journey.yaml legitimately became multi-document", len(docs))
	}
	var entries []IngressEntry
	if len(docs) == 1 {
		for _, rule := range docs[0].Spec.Rules {
			for _, p := range rule.HTTP.Paths {
				entries = append(entries, IngressEntry{Path: p.Path, PathType: p.PathType})
			}
		}
	}
	return entries, nil
}
