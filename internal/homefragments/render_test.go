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
// sources (render_manifest_test.go covers those).
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

// TestRenderMarkdown_HeadingLevels proves h1 (the page title) is dropped
// (text survives, wrapper does not) while h2/h3 survive as real elements —
// home-fragments.yaml: "never render source h1".
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
		t.Errorf("h1 TEXT should still survive (unwrapped), got: %s", got)
	}
	if !strings.Contains(got, "<h2>Section</h2>") {
		t.Errorf("expected h2 to survive as a real element, got: %s", got)
	}
	if !strings.Contains(got, "<h3>Subsection</h3>") {
		t.Errorf("expected h3 to survive as a real element, got: %s", got)
	}
}
