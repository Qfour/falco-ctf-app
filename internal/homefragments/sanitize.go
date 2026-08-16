package homefragments

import (
	"strings"

	"golang.org/x/net/html"
)

// allowedElements is the sanitize allowlist from docs-site/home-fragments.yaml
// (`sanitize_allowlist.elements`). Every other element is dropped — its
// children are kept (re-parented to the dropped node's parent) EXCEPT for
// explicitly_forbidden elements (script/style/iframe/object/embed/form/
// input/button), whose children (and text, e.g. inline JS inside <script>)
// are dropped entirely, never re-parented as loose text.
//
// h1 is intentionally absent. home-fragments.yaml: "never render source h1
// — H1 is the docs-site page title, redundant with the panel label the
// portal chrome already shows". This is enforced at the markdown-SOURCE
// stage, not here: cmd/gen-home-fragments strips a whole_file panel's
// leading "# title" line (select.go's StripLeadingH1) before RenderMarkdown
// ever runs, and a heading-selected panel (intro) never includes the
// source's h1 in its selected section to begin with — so no <h1> node is
// ever produced for this sanitizer to see.
//
// 2026-08-16 merge-review fixup (R2 F1): an earlier revision of this
// function relied on the generic "disallowed, not forbidden -> drop
// wrapper, keep children" rule below to handle a literal <h1> if goldmark
// ever emitted one, on the theory that the re-parented title TEXT surviving
// as an unwrapped text node was "harmless". It was not: that text rendered
// as a bare, unstyled line ahead of the first real <p> in the story/
// cheatsheet panels, duplicating the <summary> label the Home panel already
// shows. The fix is the source-stage strip described above (an <h1> must
// never be PRODUCED, not merely handled gracefully once produced) — this
// sanitizer intentionally still has no h1-specific branch, because after
// the fix there is nothing left for one to do.
var allowedElements = map[string]bool{
	"p":          true,
	"h2":         true,
	"h3":         true,
	"ul":         true,
	"ol":         true,
	"li":         true,
	"strong":     true,
	"em":         true,
	"code":       true,
	"pre":        true,
	"blockquote": true,
	"hr":         true,
	// table/thead/tbody/tr/th/td: added to home-fragments.yaml's
	// sanitize_allowlist.elements (2026-08-16 merge-review fixup, R1 HIGH —
	// manifest now matches this implementation) because story.md's mandated
	// whole_file panel and all 4 existing rule-explain.md files use a
	// markdown table as their only structured-data device; the manifest's
	// own note calls story.md "safe to render whole", which only holds if
	// its table renders as a table, not as dropped noise. No attributes on
	// any of these six elements either, same as every other allowed
	// element — security-reviewed and approved (P23-5 5x review).
	"table": true,
	"thead": true,
	"tbody": true,
	"tr":    true,
	"th":    true,
	"td":    true,
}

// forbiddenElements mirrors home-fragments.yaml's explicitly_forbidden list.
// These are checked FIRST and their entire subtree (including text nodes,
// e.g. inline JS/CSS source text inside <script>/<style>) is discarded — the
// "drop node, keep children" rule that applies to other disallowed elements
// does NOT apply here, since keeping a <script>'s text content as loose text
// would leak raw JS source into the page (harmless as text but confusing)
// and, more importantly, a similar node in a real attack payload (e.g. an
// <iframe> whose "children" is nothing but whose presence is the entire
// attack) must not have a code path that could ever preserve its tag.
var forbiddenElements = map[string]bool{
	"script": true, "style": true, "iframe": true, "object": true,
	"embed": true, "form": true, "input": true, "button": true,
}

// Sanitize walks parsed HTML (the output of markdown-to-HTML conversion —
// see render.go) and rewrites it to only the elements in allowedElements,
// with ALL attributes stripped from every retained element (home-fragments.yaml:
// "no attributes on any element — not even class/id"). This must run AFTER
// markdown-to-HTML conversion per the manifest's code_span_gotcha: running a
// tag-stripping pass over raw markdown source would misinterpret placeholder
// angle brackets inside inline code (`<pid>`, `<NN>-<slug>`) as HTML tags,
// since goldmark has not yet escaped them into &lt;pid&gt; inside a <code>
// text node.
//
// Link policy (home-fragments.yaml link_policy, v1 default): <a> is not in
// the allowlist, so an anchor's children are kept but the anchor itself is
// dropped — a markdown link `[label](url)` becomes plain "label" text, never
// a clickable link and never the raw URL. No href/src survives on any
// element.
//
// Disallowed-but-not-forbidden elements (e.g. h1, span, div, a, table if a
// future source needs something not in this allowlist) are dropped but
// their children are RE-PARENTED in place — text and allowed-descendant
// structure survives, only the disallowed wrapper itself is removed. This
// matches "an anchor's children are kept" above and generalizes it: the
// allowlist controls STRUCTURE, not content survival.
func Sanitize(n *html.Node) {
	sanitizeChildren(n)
}

// sanitizeChildren processes n's child list. It mutates n's children in
// place: forbidden nodes (and their whole subtree) are unlinked, allowed
// element nodes are stripped of attributes and recursed into, and any other
// node (disallowed element, unknown node type) is replaced by its own
// (already-sanitized) children spliced into n at the same position — never
// left as an unwrapped tag, never dropped-with-content.
func sanitizeChildren(n *html.Node) {
	child := n.FirstChild
	for child != nil {
		next := child.NextSibling
		sanitizeNode(n, child)
		child = next
	}
}

// sanitizeNode decides node's fate and recurses. n is node's current parent
// at call time (node has not been unlinked yet).
func sanitizeNode(parent *html.Node, node *html.Node) {
	switch node.Type {
	case html.ElementNode:
		tag := strings.ToLower(node.Data)
		if forbiddenElements[tag] {
			parent.RemoveChild(node)
			return
		}
		if allowedElements[tag] {
			node.Attr = nil
			sanitizeChildren(node)
			return
		}
		// Disallowed, not forbidden: drop the wrapper, keep children in
		// place. Recurse into the children FIRST (they may themselves be
		// forbidden/disallowed), then splice the resulting sanitized
		// children into parent where node currently sits, then remove node.
		sanitizeChildren(node)
		for c := node.FirstChild; c != nil; {
			nc := c.NextSibling
			node.RemoveChild(c)
			parent.InsertBefore(c, node)
			c = nc
		}
		parent.RemoveChild(node)
	case html.TextNode:
		// Text always survives verbatim; html.Render (used by the caller)
		// HTML-escapes text node content automatically, so raw "<"/"&"
		// inside a code-span's TEXT (as opposed to a real child element) is
		// re-escaped on render, not passed through as live markup — this is
		// what makes the code_span_gotcha placeholders
		// (`<pid>`, `<NN>-<slug>`) safe: goldmark already turned them into
		// TEXT content of a <code> element by the time Sanitize ever sees
		// this tree, so they round-trip as literal text through render too.
		return
	case html.CommentNode, html.DoctypeNode:
		parent.RemoveChild(node)
	default:
		// DocumentNode / ErrorNode etc. should not appear as a child in the
		// fragments this package produces (see render.go, which parses a
		// <body> fragment, not a full document) — fail-soft: recurse rather
		// than assume, so if one somehow appears its children still get
		// sanitized instead of silently passing through unsanitized.
		sanitizeChildren(node)
	}
}
