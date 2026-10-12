package view

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
)

// SVG allow-list sanitizer (ADR-0034 D9 (a), V6).
//
// An SVG is executable markup: <script>, <foreignObject> (which embeds HTML),
// on* attributes, <animate>/<set> (which can rewrite an href after parsing),
// xml:base, <?xml-stylesheet?>, an external <!ENTITY>, a url() to another
// origin. A deny-list of those names is the wrong shape — a name nobody
// listed (the next SVG feature) goes through. So this is an ALLOW-list on
// (namespace, element) and (namespace, attribute), with a value pattern per
// attribute; anything the list does not name, in any namespace, is an error.
// An XHTML <script> (xmlns="http://www.w3.org/1999/xhtml") is not an svg
// element, so it falls out for the same reason as <set>, with no special case.
//
// It runs when the registry is built (buildAssetRegistry), so a bad SVG is a
// START-UP failure of the scoreboard, never a runtime strip and never a file
// that quietly serves. The parse is encoding/xml in strict mode with no
// Entity map: an undefined entity is a parse error, and a <!ENTITY> or
// <!DOCTYPE> arrives as a Directive token, refused below.
//
// What the list leaves out on purpose: href and xlink:href (so no <use>, no
// <image>, no reference of any kind, not even to "#id"), style and class (so
// no url() inside a style), <style>, <title>, <text>, <defs>, gradients,
// filters, clip paths, masks and every non-whitespace text node. A glyph here
// is single-colour fill geometry; if a future glyph needs one of these, the
// change is a new line in this list and a security-engineer review of it.
const (
	svgNS = "http://www.w3.org/2000/svg"

	// maxSVGBytes / maxSVGElements bound a single glyph (the 8 shipped ones are
	// under 0.5 KB and 6 elements): a larger file is not a glyph.
	maxSVGBytes    = 4096
	maxSVGElements = 32
)

// svgElements is the (namespace, element) allow-list.
var svgElements = map[xml.Name]bool{
	{Space: svgNS, Local: "svg"}:     true,
	{Space: svgNS, Local: "g"}:       true,
	{Space: svgNS, Local: "path"}:    true,
	{Space: svgNS, Local: "circle"}:  true,
	{Space: svgNS, Local: "ellipse"}: true,
	{Space: svgNS, Local: "rect"}:    true,
}

var (
	svgNumberRe = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?$`)
	// svgPathDataRe is the characters of path data: command letters, numbers,
	// separators. No quote, paren, colon, ampersand or angle bracket, so no
	// url(), no entity, no markup.
	svgPathDataRe = regexp.MustCompile(`^[MmLlHhVvCcSsQqTtAaZz0-9eE.,+\- \t\r\n]+$`)
)

// svgAttributes is the (namespace, attribute) allow-list with the form each
// value must have. Every attribute is un-namespaced: an attribute in any
// namespace (xlink:href, xml:base, xmlns:foo, xml:space) is not here.
var svgAttributes = map[xml.Name]*regexp.Regexp{
	{Local: "xmlns"}:     regexp.MustCompile(`^http://www\.w3\.org/2000/svg$`),
	{Local: "viewBox"}:   regexp.MustCompile(`^0 0 24 24$`), // fixed: one coordinate system for all glyphs
	{Local: "fill"}:      regexp.MustCompile(`^(?:#fff|none)$`),
	{Local: "fill-rule"}: regexp.MustCompile(`^(?:nonzero|evenodd)$`),
	{Local: "d"}:         svgPathDataRe,
	{Local: "cx"}:        svgNumberRe,
	{Local: "cy"}:        svgNumberRe,
	{Local: "r"}:         svgNumberRe,
	{Local: "rx"}:        svgNumberRe,
	{Local: "ry"}:        svgNumberRe,
	{Local: "x"}:         svgNumberRe,
	{Local: "y"}:         svgNumberRe,
	{Local: "width"}:     svgNumberRe,
	{Local: "height"}:    svgNumberRe,
}

// svgName spells an xml.Name the way an error should show it: the namespace
// is part of the identity, so it is part of the message.
func svgName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return "{" + n.Space + "}" + n.Local
}

// isXMLSpace reports whether b is XML whitespace (the only text a glyph may
// contain, between its elements).
func isXMLSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

// sanitizeSVG returns nil only if data is a well-formed SVG made entirely of
// allow-listed elements and attributes. The error names the asset and the
// first defect.
func sanitizeSVG(name string, data []byte) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("static asset %q: svg: "+format, append([]any{name}, args...)...)
	}
	if len(data) > maxSVGBytes {
		return fail("%d bytes, more than the %d a glyph may take", len(data), maxSVGBytes)
	}
	dec := xml.NewDecoder(bytes.NewReader(data)) // Strict, no Entity map, no CharsetReader
	var depth, roots, elements int
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail("not well-formed XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if roots++; roots > 1 {
					return fail("more than one root element")
				}
				if t.Name != (xml.Name{Space: svgNS, Local: "svg"}) {
					return fail("root element is %s, want {%s}svg", svgName(t.Name), svgNS)
				}
			}
			if elements++; elements > maxSVGElements {
				return fail("more than %d elements", maxSVGElements)
			}
			if !svgElements[t.Name] {
				return fail("element %s is not allowed", svgName(t.Name))
			}
			seen := make(map[xml.Name]bool, len(t.Attr))
			for _, a := range t.Attr {
				form, ok := svgAttributes[a.Name]
				if !ok {
					return fail("attribute %s on <%s> is not allowed", svgName(a.Name), t.Name.Local)
				}
				if seen[a.Name] {
					return fail("attribute %s on <%s> is repeated", svgName(a.Name), t.Name.Local)
				}
				seen[a.Name] = true
				if !form.MatchString(a.Value) {
					return fail("attribute %s on <%s> has a value outside its allowed form", svgName(a.Name), t.Name.Local)
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			for _, b := range t {
				if !isXMLSpace(b) {
					return fail("text content is not allowed (only whitespace between elements)")
				}
			}
		case xml.Comment:
			return fail("a comment is not allowed")
		case xml.ProcInst:
			return fail("processing instruction <?%s ...?> is not allowed (an <?xml-stylesheet?> pulls in a stylesheet; the XML declaration is not needed either)", t.Target)
		case xml.Directive:
			return fail("a <!...> declaration is not allowed (DOCTYPE / ENTITY / ELEMENT)")
		}
	}
	if roots == 0 {
		return fail("no root element")
	}
	return nil
}
