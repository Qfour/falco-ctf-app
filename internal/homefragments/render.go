package homefragments

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// md is a goldmark instance with the GFM table extension enabled (part of
// goldmark's own module — github.com/yuin/goldmark/extension — not a
// separate dependency). story.md and every current rule-explain.md use a
// markdown table as their only structured-data device; without this
// extension goldmark's CommonMark-only default parser renders a table block
// as a single flattened <p> (observed empirically — see
// render_test.go's TestRenderMarkdown_Table), which the sanitizer would then
// pass through as garbled prose instead of structured rows. No other GFM
// extras (strikethrough, autolink, task list, linkify) are enabled — the
// manifest's sources do not use them, and enabling autolink/linkify in
// particular would work against the "no <a>" sanitize policy for no
// benefit.
var md = goldmark.New(goldmark.WithExtensions(extension.Table))

// RenderMarkdown converts one markdown source fragment to sanitized,
// gen-time-fixed HTML, per docs-site/home-fragments.yaml's pipeline order:
//  1. flatten `!!! type "title"` admonitions to plain markdown (BEFORE
//     markdown parsing — goldmark has no built-in admonition extension).
//  2. markdown -> HTML via goldmark (default parser: no raw-HTML passthrough
//     extension enabled, so any literal HTML in a source .md — none exists
//     today, checked 2026-08-16 — would already be text-escaped by goldmark
//     itself before Sanitize ever runs, not a bypass route).
//  3. parse the resulting HTML into a tree and Sanitize it against the
//     allowlist (this order is the code_span_gotcha fix: placeholder angle
//     brackets like `<pid>` are already escaped into safe text INSIDE a
//     <code> element by goldmark's markdown parser at this point, not raw
//     text a regex could misparse as a tag).
//  4. re-serialize the sanitized tree back to an HTML string.
//
// The returned string contains ONLY elements/attributes from the
// sanitize_allowlist — see sanitize.go's Sanitize doc for the exact rules.
func RenderMarkdown(src string) (string, error) {
	flattened := flattenAdmonitions(src)

	var buf bytes.Buffer
	if err := md.Convert([]byte(flattened), &buf); err != nil {
		return "", fmt.Errorf("markdown convert: %w", err)
	}

	// Parse as a fragment within a <body> context, matching how goldmark's
	// output is meant to be embedded (a sequence of block-level elements,
	// not a full document) — html.ParseFragment requires a context node
	// whose DataAtom is consistent with its Data (atom.Body for "body").
	body := &html.Node{Type: html.ElementNode, Data: "body", DataAtom: atom.Body}
	nodes, err := html.ParseFragment(&buf, body)
	if err != nil {
		return "", fmt.Errorf("html parse: %w", err)
	}

	root := &html.Node{Type: html.ElementNode, Data: "body"}
	for _, n := range nodes {
		root.AppendChild(n)
	}
	Sanitize(root)

	var out bytes.Buffer
	for c := root.FirstChild; c != nil; c = c.NextSibling {
		if err := html.Render(&out, c); err != nil {
			return "", fmt.Errorf("html render: %w", err)
		}
	}
	return strings.TrimSpace(out.String()), nil
}
