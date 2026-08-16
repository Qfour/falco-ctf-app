package homefragments

import (
	"regexp"
	"strings"
	"testing"
)

// TestRenderMarkdown_StripsScriptAndEventAttrs proves a maliciously-shaped
// source (as if a compromised/careless content edit introduced raw HTML)
// cannot survive the pipeline as live markup — this is the "allowlist
// outside is zero" requirement from the P23-5 task spec, exercised directly
// against attack-shaped input rather than only against today's clean
// sources (manifest_verified_test.go covers those, running the real
// docs-site/docs/*.md + challenges/*/rule-explain.md sources through this
// same pipeline and asserting no hint/flag/answer text survives).
func TestRenderMarkdown_StripsScriptAndEventAttrs(t *testing.T) {
	src := "# title\n\n<script>alert(1)</script>\n\n" +
		"<p onclick=\"evil()\" style=\"color:red\" class=\"x\">hi</p>\n\n" +
		"<a href=\"https://evil.example/\">click</a>\n\n" +
		"<iframe src=\"https://evil.example/\"></iframe>\n\n" +
		"<form><input><button>go</button></form>\n"

	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}

	forbidden := []string{
		"<script", "</script>", "<style", "<iframe", "<object", "<embed",
		"<form", "<input", "<button", "onclick", "style=", "href=", "src=",
		"class=", "id=", "alert(1)", "evil.example",
	}
	for _, f := range forbidden {
		if strings.Contains(strings.ToLower(got), strings.ToLower(f)) {
			t.Errorf("output contains forbidden substring %q\noutput: %s", f, got)
		}
	}
	// The <a> label text must survive as plain text (link_policy: v1 default
	// drops href, keeps the label) even though the href/URL must not.
	if !strings.Contains(got, "click") {
		t.Errorf("expected anchor label text 'click' to survive as plain text, got: %s", got)
	}
	// <script> content must NOT survive as loose text either (forbidden
	// elements drop their whole subtree, not just the tag).
	if strings.Contains(got, "alert") {
		t.Errorf("script body leaked as text: %s", got)
	}
}

// TestRenderMarkdown_NoAttributesSurviveAtAll is a blunter version of the
// above: after rendering ANY markdown that goldmark can produce headings/
// emphasis/lists/code from, no `="` attribute-assignment substring should
// ever appear in the output, since the allowlist strips attributes from
// every retained element unconditionally.
func TestRenderMarkdown_NoAttributesSurviveAtAll(t *testing.T) {
	src := "# T\n\n## H2\n\n### H3\n\n" +
		"**bold** *em* `code` \n\n" +
		"- item one\n- item two\n\n" +
		"1. first\n2. second\n\n" +
		"```bash\necho hi\n```\n\n" +
		"> quoted\n\n---\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	attrRe := regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9]*\s+[a-zA-Z-]+=`)
	if attrRe.MatchString(got) {
		t.Errorf("output contains an element attribute, want none: %s", got)
	}
}

// TestRenderMarkdown_CodeSpanPlaceholdersSurviveAsLiteralText proves the
// code_span_gotcha fix: placeholder angle brackets inside inline code
// (`<pid>`, `<NN>-<slug>`) must render as literal text inside <code>, never
// be interpreted as an HTML tag and stripped/mangled by the sanitizer. This
// is the exact scenario home-fragments.yaml calls out by name.
func TestRenderMarkdown_CodeSpanPlaceholdersSurviveAsLiteralText(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"pid placeholder", "kill -9 `<pid>`\n", "&lt;pid&gt;"},
		{"NN-slug placeholder", "cd `/opt/ctf/missions/<NN>-<slug>/`\n", "&lt;NN&gt;-&lt;slug&gt;"},
		{"mission-id placeholder", "curl `/api/<mission-id>/status`\n", "&lt;mission-id&gt;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderMarkdown(tc.src)
			if err != nil {
				t.Fatalf("RenderMarkdown: %v", err)
			}
			if !strings.Contains(got, "<code>") {
				t.Fatalf("expected a <code> element, got: %s", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("expected escaped placeholder %q inside <code>, got: %s", tc.want, got)
			}
			// The literal, unescaped tag-looking substring must never appear
			// (that would mean it got interpreted as a real element and
			// either survived or got tag-stripped, losing the brackets).
			raw := strings.TrimSuffix(strings.TrimPrefix(tc.want, "&lt;"), "&gt;")
			if strings.Contains(got, "<"+strings.Split(raw, "&gt;")[0]+">") {
				t.Errorf("placeholder leaked as a literal (unescaped) tag: %s", got)
			}
		})
	}
}

// TestRenderMarkdown_Admonition proves a `!!! tip "title"` block becomes a
// <blockquote> with the title as a leading <strong>, matching
// home-fragments.yaml's admonition_handling note, and that the indented
// body stays associated with the title rather than merging into whatever
// paragraph precedes it.
func TestRenderMarkdown_Admonition(t *testing.T) {
	src := "intro paragraph\n\n" +
		"!!! tip \"ワークスペースとの併用\"\n" +
		"    手を動かす環境は各自のワークスペースです。\n" +
		"    このサイトは読み物として参照してください。\n\n" +
		"trailing paragraph\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(got, "<blockquote>") {
		t.Fatalf("expected a <blockquote>, got: %s", got)
	}
	if !strings.Contains(got, "<strong>ワークスペースとの併用</strong>") {
		t.Errorf("expected the admonition title as a leading <strong>, got: %s", got)
	}
	if !strings.Contains(got, "手を動かす環境は各自のワークスペースです。") {
		t.Errorf("expected the admonition body text to survive, got: %s", got)
	}
	// The body text must be INSIDE the blockquote, not merged into the
	// preceding "intro paragraph" — check ordering: intro appears before
	// the blockquote opens, body appears after.
	introIdx := strings.Index(got, "intro paragraph")
	bqIdx := strings.Index(got, "<blockquote>")
	bodyIdx := strings.Index(got, "手を動かす環境")
	if introIdx < 0 || bqIdx < 0 || bodyIdx < 0 || !(introIdx < bqIdx && bqIdx < bodyIdx) {
		t.Errorf("expected intro < blockquote-open < body ordering, got: %s", got)
	}
}

// TestRenderMarkdown_Table proves the app-lead allowlist extension
// (table/thead/tbody/tr/th/td — see sanitize.go's comment on allowedElements)
// renders a markdown table as a real HTML table rather than dropping it,
// since story.md's mandated whole-file panel is a table plus a short intro/
// admonition and would otherwise lose all of its structured content.
func TestRenderMarkdown_Table(t *testing.T) {
	src := "| # | Name |\n|---|---|\n| 01 | Alpha |\n| 02 | Beta |\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, want := range []string{"<table>", "<td>", "Alpha", "Beta"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in table output, got: %s", want, got)
		}
	}
}

// TestRenderMarkdown_TableAlignmentAttrsStripped proves goldmark's GFM table
// extension — which emits `style="text-align:..."` on <th>/<td> for
// `:---:`-style column alignment markers, confirmed empirically against
// this exact goldmark version — does not survive sanitization. This is the
// adversarial case for the app-lead table-allowlist extension (merge-review
// fixup R1 LOW): the six table elements are allowed, but Sanitize's
// unconditional `node.Attr = nil` on every allowed element must still strip
// this specific attribute goldmark itself introduces, not just attributes a
// malicious SOURCE might contain.
func TestRenderMarkdown_TableAlignmentAttrsStripped(t *testing.T) {
	src := "| A | B | C |\n|:---|:---:|---:|\n| l | c | r |\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(got, "style=") || strings.Contains(got, "text-align") {
		t.Fatalf("expected goldmark's table alignment style= attribute to be stripped, got: %s", got)
	}
	for _, want := range []string{"<th>A</th>", "<th>B</th>", "<th>C</th>", "<td>l</td>", "<td>c</td>", "<td>r</td>"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected attribute-free %q, got: %s", want, got)
		}
	}
}

// TestRenderMarkdown_ForeignContentTagsAndAttrsNeverSurviveLive proves raw
// <svg>/<math> "foreign content" (HTML5 elements with their own
// sub-grammar, historically a sanitizer-bypass vector in other tools since
// naive allowlist walkers sometimes special-case only the outer tag) never
// produces a LIVE tag or attribute in the output — no <svg>, no <script>,
// no onload=, no attribute-shaped substring of any kind.
//
// What actually happens (verified empirically against this goldmark
// version, adjusted from this test's first draft which wrongly assumed
// Sanitize's tree-walker would see these as element nodes): goldmark's
// DEFAULT parser configuration (no html.WithUnsafe()) treats ALL raw HTML
// — including <svg>, <script>, <text>, <math>, <mtext> and their closing
// tags — as unsafe and replaces EVERY such tag with an HTML comment
// ("<!-- raw HTML omitted -->") at the markdown-to-HTML conversion step,
// i.e. BEFORE Sanitize's tree walker ever runs. Sanitize.go's
// allowedElements/forbiddenElements maps for svg/script/math/etc are
// therefore defense-in-depth for a HYPOTHETICAL future config change (e.g.
// someone adding goldmark.WithRendererOptions(html.WithUnsafe()) down the
// line) — under TODAY's configuration this specific attack shape never
// reaches that code path at all, goldmark's own raw-HTML lockout is what
// stops it. What DOES survive is the plain TEXT that sat between the
// stripped tags ("alert(2)", "hidden", "mathtext") — inert display text,
// never live markup, never an attribute — which
// TestRenderMarkdown_ForeignContentInertTextSurvivesAsPlainText below pins
// explicitly so this is a documented, verified characteristic rather than
// an unexamined side effect.
func TestRenderMarkdown_ForeignContentTagsAndAttrsNeverSurviveLive(t *testing.T) {
	src := "before\n\n<svg onload=\"alert(1)\"><script>alert(2)</script><text>hidden</text></svg>\n\n" +
		"<math><mtext>mathtext</mtext></math>\n\nafter\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, forbidden := range []string{"<svg", "<math", "<script", "<text", "<mtext", "onload", "onload=", "alert(1)"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(forbidden)) {
			t.Errorf("output contains forbidden substring %q from foreign content, got: %s", forbidden, got)
		}
	}
	attrRe := regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9]*\s+[a-zA-Z-]+=`)
	if attrRe.MatchString(got) {
		t.Errorf("output contains an element attribute, want none: %s", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("expected surrounding plain paragraphs to survive, got: %s", got)
	}
}

// TestRenderMarkdown_ForeignContentInertTextSurvivesAsPlainText documents
// (see the sibling test's doc above) that the INLINE TEXT that sat between
// stripped raw-HTML tags DOES survive as plain paragraph text — this is
// safe (no tag, no attribute, no script execution: it is indistinguishable
// from any other prose in a <p>) but is worth pinning explicitly so a
// reader does not mistake the sibling test's "no live tags" assertion for
// "no leftover text at all".
func TestRenderMarkdown_ForeignContentInertTextSurvivesAsPlainText(t *testing.T) {
	src := "<svg><script>alert(2)</script><text>hidden</text></svg>\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(got, "<p>") {
		t.Fatalf("expected the inert text to still be wrapped in a plain <p>, got: %s", got)
	}
	if !strings.Contains(got, "alert(2)") || !strings.Contains(got, "hidden") {
		t.Errorf("expected the stripped tags' inline text to survive as inert plain text, got: %s", got)
	}
}

// TestRenderMarkdown_CommentsAndCDATADropped proves HTML comments and CDATA
// sections do not survive into the output. Comments are a classic vector
// for smuggling markup past a naive string-based filter (e.g.
// "<!--<script>-->" un-commented by a later processing step) and CDATA is
// XML/XHTML syntax that has no defined meaning in HTML5 parsing (browsers
// treat "<![CDATA[" as a bogus comment) — either way, nothing from inside
// either construct should appear in sanitized output.
func TestRenderMarkdown_CommentsAndCDATADropped(t *testing.T) {
	src := "before\n\n<!-- <script>alert(1)</script> comment payload -->\n\n" +
		"<![CDATA[ <script>alert(2)</script> cdata payload ]]>\n\nafter\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, forbidden := range []string{"<script", "alert(1)", "alert(2)", "comment payload", "cdata payload", "CDATA"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("output contains forbidden substring %q from comment/CDATA, got: %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("expected surrounding plain paragraphs to survive, got: %s", got)
	}
}

// TestRenderMarkdown_HeadingLevels proves RenderMarkdown itself (the
// sanitizer layer, independent of the generator's pre-processing) never
// lets an <h1> element survive, while h2/h3 survive as real elements.
// This is deliberately a lower-level guarantee than "no h1 title leaks into
// a Home panel" — that end-to-end guarantee is cmd/gen-home-fragments'
// job (StripLeadingH1 removes the leading "# title" line from whole_file
// sources BEFORE they ever reach RenderMarkdown, so goldmark never emits an
// <h1> node for a real Home panel — see select.go's StripLeadingH1 doc and
// merge-review fixup R2 F1). RenderMarkdown does not know or care whether
// its caller pre-stripped a title; it must still never let a raw <h1> THAT
// DOES reach it survive as a wrapped element, and today that means the
// title TEXT is re-parented as unwrapped text (harmless in isolation — the
// R2 F1 bug was specifically about that text leaking into a REAL panel
// where the generator had NOT pre-stripped it, not about this function's
// own drop-wrapper behavior being wrong).
func TestRenderMarkdown_HeadingLevels(t *testing.T) {
	src := "# Page Title\n\n## Section\n\n### Subsection\n\nbody\n"
	got, err := RenderMarkdown(src)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(got, "<h1") {
		t.Errorf("h1 must not survive as an element, got: %s", got)
	}
	if !strings.Contains(got, "Page Title") {
		t.Errorf("h1 TEXT should still survive (unwrapped) at the RenderMarkdown layer — callers that care about title leakage must pre-strip, as cmd/gen-home-fragments now does, got: %s", got)
	}
	if !strings.Contains(got, "<h2>Section</h2>") {
		t.Errorf("expected h2 to survive as a real element, got: %s", got)
	}
	if !strings.Contains(got, "<h3>Subsection</h3>") {
		t.Errorf("expected h3 to survive as a real element, got: %s", got)
	}
}
