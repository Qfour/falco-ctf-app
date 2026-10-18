package specparity

// ADR-0039 S1 / ADR-0005 V8: the walker is proven fail-closed against small
// synthetic specs (never the real docs/openapi-*.yaml: those are exercised by
// TestAPISpec_TextOriginDeclared in textorigin_specs_test.go). Each case mutates one
// thing in an otherwise valid document and names the JSON pointer the
// failure must point at; the baseline case proves the mutations are the only
// reason for red.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func specFromYAML(t *testing.T, doc string) *Spec {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadSpec(path)
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	return s
}

// textOriginBase is a valid document exercising every place the walk must
// reach: a component property, an array items, additionalProperties, allOf /
// anyOf / oneOf, a `type: [string, "null"]`, a component parameter, an inline
// parameter, a requestBody, a response, a response header and
// components.{responses,requestBodies,headers}. 17 string nodes.
const textOriginBase = `
openapi: 3.1.0
paths:
  /a/{id}:
    parameters:
      - in: query
        name: q
        schema: {type: string, x-ctf-text-origin: participant-opaque}
    post:
      parameters:
        - $ref: "#/components/parameters/Id"
        - in: header
          name: X-H
          schema: {type: string, x-ctf-text-origin: token}
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                note: {type: string, x-ctf-text-origin: participant-block}
      responses:
        "200":
          description: ok
          headers:
            X-Out:
              schema: {type: string, x-ctf-text-origin: operator}
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Thing"}
components:
  parameters:
    Id:
      in: path
      name: id
      schema: {type: string, pattern: "^[a-z]+$", x-ctf-text-origin: token}
  schemas:
    Thing:
      type: object
      properties:
        name: {type: string, x-ctf-text-origin: participant-inline}
        maybe: {type: [string, "null"], x-ctf-text-origin: operator}
        tags:
          type: array
          items: {type: string, x-ctf-text-origin: operator}
        extra:
          type: object
          additionalProperties: {type: string, x-ctf-text-origin: operator}
        kind: {type: string, enum: [a, b], x-ctf-text-origin: enum}
        both:
          allOf:
            - {type: string, x-ctf-text-origin: token}
        either:
          anyOf:
            - {type: string, x-ctf-text-origin: token}
            - {type: integer}
        one:
          oneOf:
            - {type: string, x-ctf-text-origin: token}
            - {type: boolean}
        link: {$ref: "#/components/schemas/Other"}
    Other: {type: string, x-ctf-text-origin: operator}
  responses:
    Gone:
      description: gone
      content:
        text/plain:
          schema: {type: string, x-ctf-text-origin: operator}
  requestBodies:
    Form:
      content:
        application/json:
          schema: {type: string, x-ctf-text-origin: participant-opaque}
  headers:
    Rate:
      schema: {type: string, x-ctf-text-origin: operator}
`

const textOriginBaseNodes = 17

func TestTextOrigin_BaselineIsGreenAndCounted(t *testing.T) {
	rep := specFromYAML(t, textOriginBase).TextOrigin()
	if len(rep.Violations) != 0 {
		t.Fatalf("baseline must be clean, got:\n%s", strings.Join(rep.Violations, "\n"))
	}
	if len(rep.Nodes) != textOriginBaseNodes {
		t.Fatalf("baseline has %d string nodes, want %d (the walk dropped or invented one): %v", len(rep.Nodes), textOriginBaseNodes, rep.Nodes)
	}
	want := map[string]int{
		OriginParticipantInline: 1,
		OriginParticipantBlock:  1,
		OriginParticipantOpaque: 2,
		OriginOperator:          7,
		OriginToken:             5,
		OriginEnum:              1,
	}
	if !reflect.DeepEqual(rep.Counts, want) {
		t.Fatalf("counts = %v, want %v", rep.Counts, want)
	}
}

func TestTextOrigin_Mutations(t *testing.T) {
	cases := []struct {
		name string
		from string // substring of the baseline to replace
		to   string
		last bool // replace the LAST occurrence of from (it is not unique)
		// want: every substring must appear in the Violations text
		want []string
	}{
		{
			name: "a property without the key",
			from: `name: {type: string, x-ctf-text-origin: participant-inline}`,
			to:   `name: {type: string}`,
			want: []string{"/components/schemas/Thing/properties/name: string node without x-ctf-text-origin"},
		},
		{
			name: "array items without the key",
			from: `items: {type: string, x-ctf-text-origin: operator}`,
			to:   `items: {type: string}`,
			want: []string{"/components/schemas/Thing/properties/tags/items: string node without"},
		},
		{
			name: "additionalProperties without the key",
			from: `additionalProperties: {type: string, x-ctf-text-origin: operator}`,
			to:   `additionalProperties: {type: string}`,
			want: []string{"/components/schemas/Thing/properties/extra/additionalProperties: string node without"},
		},
		{
			name: "allOf member without the key",
			from: `- {type: string, x-ctf-text-origin: token}
        either:`,
			to: `- {type: string}
        either:`,
			want: []string{"/components/schemas/Thing/properties/both/allOf/0: string node without"},
		},
		{
			name: "type list containing string without the key",
			from: `maybe: {type: [string, "null"], x-ctf-text-origin: operator}`,
			to:   `maybe: {type: [string, "null"]}`,
			want: []string{"/components/schemas/Thing/properties/maybe: string node without"},
		},
		{
			name: "component parameter without the key",
			from: `schema: {type: string, pattern: "^[a-z]+$", x-ctf-text-origin: token}`,
			to:   `schema: {type: string, pattern: "^[a-z]+$"}`,
			want: []string{"/components/parameters/Id/schema: string node without"},
		},
		{
			name: "path-level parameter without the key",
			from: `schema: {type: string, x-ctf-text-origin: participant-opaque}
    post:`,
			to: `schema: {type: string}
    post:`,
			want: []string{"/paths/~1a~1{id}/parameters/0/schema: string node without"},
		},
		{
			name: "inline operation parameter without the key",
			from: `schema: {type: string, x-ctf-text-origin: token}
      requestBody:`,
			to: `schema: {type: string}
      requestBody:`,
			want: []string{"/paths/~1a~1{id}/post/parameters/1/schema: string node without"},
		},
		{
			name: "requestBody property without the key",
			from: `note: {type: string, x-ctf-text-origin: participant-block}`,
			to:   `note: {type: string}`,
			want: []string{"/paths/~1a~1{id}/post/requestBody/content/application~1json/schema/properties/note: string node without"},
		},
		{
			name: "response header without the key",
			from: `schema: {type: string, x-ctf-text-origin: operator}
          content:`,
			to: `schema: {type: string}
          content:`,
			want: []string{"/paths/~1a~1{id}/post/responses/200/headers/X-Out/schema: string node without"},
		},
		{
			name: "components.responses string without the key",
			from: `text/plain:
          schema: {type: string, x-ctf-text-origin: operator}`,
			to: `text/plain:
          schema: {type: string}`,
			want: []string{"/components/responses/Gone/content/text~1plain/schema: string node without"},
		},
		{
			name: "components.requestBodies string without the key",
			from: `schema: {type: string, x-ctf-text-origin: participant-opaque}
  headers:`,
			to: `schema: {type: string}
  headers:`,
			want: []string{"/components/requestBodies/Form/content/application~1json/schema: string node without"},
		},
		{
			name: "components.headers string without the key",
			from: `schema: {type: string, x-ctf-text-origin: operator}
`,
			to: `schema: {type: string}
`,
			last: true,
			want: []string{"/components/headers/Rate/schema: string node without"},
		},
		{
			name: "a word outside the vocabulary",
			from: `name: {type: string, x-ctf-text-origin: participant-inline}`,
			to:   `name: {type: string, x-ctf-text-origin: participant}`,
			want: []string{`/components/schemas/Thing/properties/name: x-ctf-text-origin: "participant" is not in the vocabulary`},
		},
		{
			name: "a word with different case",
			from: `name: {type: string, x-ctf-text-origin: participant-inline}`,
			to:   `name: {type: string, x-ctf-text-origin: Token}`,
			want: []string{`"Token" is not in the vocabulary`},
		},
		{
			name: "a non-string value (list)",
			from: `name: {type: string, x-ctf-text-origin: participant-inline}`,
			to:   `name: {type: string, x-ctf-text-origin: [token]}`,
			want: []string{"/components/schemas/Thing/properties/name: x-ctf-text-origin must be a string"},
		},
		{
			name: "a null value",
			from: `name: {type: string, x-ctf-text-origin: participant-inline}`,
			to:   `name: {type: string, x-ctf-text-origin: null}`,
			want: []string{"/components/schemas/Thing/properties/name: string node without x-ctf-text-origin"},
		},
		{
			name: "the key on an object node",
			from: `Thing:
      type: object`,
			to: `Thing:
      x-ctf-text-origin: operator
      type: object`,
			want: []string{"/components/schemas/Thing: x-ctf-text-origin on a node that is not a string Schema Object"},
		},
		{
			name: "the key on a $ref site",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "#/components/schemas/Other", x-ctf-text-origin: operator}`,
			want: []string{"/components/schemas/Thing/properties/link: x-ctf-text-origin on a node that is not a string Schema Object"},
		},
		{
			name: "the key on an integer node",
			from: `- {type: integer}`,
			to:   `- {type: integer, x-ctf-text-origin: token}`,
			want: []string{"/components/schemas/Thing/properties/either/anyOf/1: x-ctf-text-origin on a node that is not a string Schema Object"},
		},
		{
			name: "a $ref outside the document",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "other.yaml#/components/schemas/Other"}`,
			want: []string{`/components/schemas/Thing/properties/link: $ref "other.yaml#/components/schemas/Other" is not a reference to an existing`},
		},
		{
			name: "a $ref to a missing schema",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "#/components/schemas/Nope"}`,
			want: []string{`$ref "#/components/schemas/Nope" is not a reference to an existing`},
		},
		{
			name: "a $ref to a missing parameter",
			from: `- $ref: "#/components/parameters/Id"`,
			to:   `- $ref: "#/components/parameters/Gone"`,
			want: []string{`/paths/~1a~1{id}/post/parameters/0: $ref "#/components/parameters/Gone" is not a reference to an existing`},
		},
		{
			name: "an unquoted integer key (yaml.v3 gives map[any]any) over a response",
			from: `"200":`,
			to:   `200:`,
			want: []string{"non-string mapping key at /paths/~1a~1{id}/post/responses"},
		},
		{
			name: "an integer key among the properties",
			from: `kind: {type: string, enum: [a, b], x-ctf-text-origin: enum}`,
			to:   `1: {type: string}`,
			want: []string{"non-string mapping key at /components/schemas/Thing/properties"},
		},
		{
			name: "a $ref into paths",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "#/paths/~1a~1{id}/post/requestBody"}`,
			want: []string{`/components/schemas/Thing/properties/link: $ref "#/paths/~1a~1{id}/post/requestBody" is not a reference to an existing`},
		},
		{
			name: "a $ref deeper than a component",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "#/components/schemas/Thing/properties/name"}`,
			want: []string{`$ref "#/components/schemas/Thing/properties/name" is not a reference to an existing`},
		},
		{
			name: "a $ref into a components section the walk does not visit",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "#/components/examples/Other"}`,
			want: []string{`$ref "#/components/examples/Other" is not a reference to an existing`},
		},
		{
			name: "a Schema Object $ref into components.parameters",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to:   `link: {$ref: "#/components/parameters/Id"}`,
			want: []string{`/components/schemas/Thing/properties/link: a $ref in a Schema Object position must be #/components/schemas/<Name>, got "#/components/parameters/Id"`},
		},
		{
			name: "a parameter $ref into components.schemas",
			from: `- $ref: "#/components/parameters/Id"`,
			to:   `- $ref: "#/components/schemas/Thing"`,
			want: []string{`/paths/~1a~1{id}/post/parameters/0: a $ref in a parameter position must be #/components/parameters/<Name>, got "#/components/schemas/Thing"`},
		},
		{
			name: "a response $ref into components.schemas",
			from: `        "200":
          description: ok
          headers:`,
			to: `        "200": {$ref: "#/components/schemas/Thing"}
        "201":
          description: ok
          headers:`,
			want: []string{`/paths/~1a~1{id}/post/responses/200: a $ref in a response position must be #/components/responses/<Name>, got "#/components/schemas/Thing"`},
		},
		{
			name: "a string schema in a place the walk does not know",
			from: `components:
  parameters:`,
			to: `components:
  callbacks:
    cb:
      schema: {type: string}
  parameters:`,
			want: []string{"/components/callbacks/cb/schema: a string Schema Object that the walk"},
		},
		{
			name: "a string schema hidden under a vendor key",
			from: `    Other: {type: string, x-ctf-text-origin: operator}`,
			to: `    Other: {type: string, x-ctf-text-origin: operator}
    Hidden:
      x-extra: {type: string}`,
			want: []string{"/components/schemas/Hidden/x-extra: a string Schema Object that the walk"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := textOriginBase
			if strings.Count(doc, tc.from) < 1 {
				t.Fatalf("test bug: %q not found in the baseline", tc.from)
			}
			if tc.last {
				doc = replaceLast(doc, tc.from, tc.to)
			} else {
				if n := strings.Count(doc, tc.from); n != 1 {
					t.Fatalf("test bug: %q occurs %d times in the baseline, want exactly 1", tc.from, n)
				}
				doc = strings.Replace(doc, tc.from, tc.to, 1)
			}
			rep := specFromYAML(t, doc).TextOrigin()
			if len(rep.Violations) == 0 {
				t.Fatalf("the mutation was not detected (a gate that cannot go red is not a gate)")
			}
			all := strings.Join(rep.Violations, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("violations do not contain %q; got:\n%s", w, all)
				}
			}
		})
	}
}

func replaceLast(s, from, to string) string {
	i := strings.LastIndex(s, from)
	if i < 0 {
		return s
	}
	return s[:i] + to + s[i+len(from):]
}

// TestTextOrigin_ZeroStringNodesFails: an empty extraction must read as a
// broken gate, never as "nothing to declare" (ADR-0005 V8-2).
func TestTextOrigin_ZeroStringNodesFails(t *testing.T) {
	rep := specFromYAML(t, "openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    N: {type: integer}\n").TextOrigin()
	if len(rep.Violations) != 1 || !strings.Contains(rep.Violations[0], "no string Schema Object found at all") {
		t.Fatalf("zero string nodes must be a violation, got %v", rep.Violations)
	}
}

// TestTextOrigin_VocabularyIsExactlySixDistinctWords pins the closed set: a
// change here is an ADR-0039 D2 change, not a drive-by edit.
func TestTextOrigin_VocabularyIsExactlySixDistinctWords(t *testing.T) {
	want := []string{"participant-inline", "participant-block", "participant-opaque", "operator", "token", "enum"}
	if !reflect.DeepEqual(TextOriginVocabulary, want) {
		t.Fatalf("vocabulary = %v, want %v (a change here is an ADR-0039 D2 change)", TextOriginVocabulary, want)
	}
}

// TestTextOrigin_PointerEscaping: '/' and '~' in a path or property name are
// escaped per RFC 6901 so the pointer in a failure line is followable.
func TestTextOrigin_PointerEscaping(t *testing.T) {
	doc := `
openapi: 3.1.0
paths:
  /x/{a~b}:
    get:
      parameters:
        - in: query
          name: q
          schema: {type: string}
      responses: {}
`
	rep := specFromYAML(t, doc).TextOrigin()
	all := strings.Join(rep.Violations, "\n")
	if !strings.Contains(all, "/paths/~1x~1{a~0b}/get/parameters/0/schema: string node without") {
		t.Fatalf("pointer not escaped as RFC 6901, got:\n%s", all)
	}
}

// ---- ADR-0039 S1b: D3 (d) static rules, D3 (h), D3 (e) ----

func mutateOnce(t *testing.T, doc, from, to string) string {
	t.Helper()
	if n := strings.Count(doc, from); n != 1 {
		t.Fatalf("test bug: %q occurs %d times, want exactly 1", from, n)
	}
	return strings.Replace(doc, from, to, 1)
}

// TestTextOrigin_StaticRules_Mutations is ADR-0039 V2's S1b half: each case
// breaks one rule between a word and where its node sits (or D3 (h), or the
// Schema Object $ref shape) and must go red naming the pointer.
func TestTextOrigin_StaticRules_Mutations(t *testing.T) {
	cases := []struct {
		name     string
		from, to string
		want     []string
	}{
		{
			name: "participant-opaque reachable from a response",
			from: `name: {type: string, x-ctf-text-origin: participant-inline}`,
			to:   `name: {type: string, x-ctf-text-origin: participant-opaque}`,
			want: []string{"/components/schemas/Thing/properties/name: `participant-opaque` is reachable from a response"},
		},
		{
			name: "operator text in a participant operation's request body",
			from: `note: {type: string, x-ctf-text-origin: participant-block}`,
			to:   `note: {type: string, x-ctf-text-origin: operator}`,
			want: []string{"properties/note: `operator` text in the request of POST /a/{id}"},
		},
		{
			name: "operator text in a participant operation's parameter",
			from: `schema: {type: string, x-ctf-text-origin: token}
      requestBody:`,
			to: `schema: {type: string, x-ctf-text-origin: operator}
      requestBody:`,
			want: []string{"/paths/~1a~1{id}/post/parameters/1/schema: `operator` text in the request of POST /a/{id}"},
		},
		{
			name: "operator text in the request of a component a participant operation reaches by $ref",
			from: `- $ref: "#/components/parameters/Id"`,
			to:   `- $ref: "#/components/parameters/Opr"`,
			want: []string{"/components/parameters/Opr/schema: `operator` text in the request of POST /a/{id}"},
		},
		{
			name: "a node with enum declared token",
			from: `kind: {type: string, enum: [a, b], x-ctf-text-origin: enum}`,
			to:   `kind: {type: string, enum: [a, b], x-ctf-text-origin: token}`,
			want: []string{"/components/schemas/Thing/properties/kind: has `enum`/`const` but declares \"token\""},
		},
		{
			name: "the enum word on a node without enum or const",
			from: `kind: {type: string, enum: [a, b], x-ctf-text-origin: enum}`,
			to:   `kind: {type: string, x-ctf-text-origin: enum}`,
			want: []string{"/components/schemas/Thing/properties/kind: declared `enum` but has neither"},
		},
		{
			name: "participant-inline in an array's items of a response",
			from: `items: {type: string, x-ctf-text-origin: operator}`,
			to:   `items: {type: string, x-ctf-text-origin: participant-inline}`,
			want: []string{`/components/schemas/Thing/properties/tags/items: "participant-inline" in a response must be a named property`},
		},
		{
			name: "participant-inline in additionalProperties of a response",
			from: `additionalProperties: {type: string, x-ctf-text-origin: operator}`,
			to:   `additionalProperties: {type: string, x-ctf-text-origin: participant-block}`,
			want: []string{`/components/schemas/Thing/properties/extra/additionalProperties: "participant-block" in a response must be a named property`},
		},
		{
			name: "participant-inline in a response header",
			from: `schema: {type: string, x-ctf-text-origin: operator}
          content:`,
			to: `schema: {type: string, x-ctf-text-origin: participant-inline}
          content:`,
			want: []string{`/paths/~1a~1{id}/post/responses/200/headers/X-Out/schema: "participant-inline" in a response must be a named property`},
		},
		{
			name: "a participant-* property name reused for an operator string in a response",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to: `link: {$ref: "#/components/schemas/Other"}
        nested:
          type: object
          properties:
            name: {type: string, x-ctf-text-origin: operator}`,
			want: []string{`/components/schemas/Thing/properties/nested/properties/name: property name "name" is a participant-text name in responses`, `/components/schemas/Thing/properties/name: property name "name"`},
		},
		{
			name: "enum without type",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to: `link: {$ref: "#/components/schemas/Other"}
        loose: {enum: [a, b]}`,
			want: []string{"/components/schemas/Thing/properties/loose: a Schema Object with enum/const and no `type`"},
		},
		{
			name: "const without type",
			from: `link: {$ref: "#/components/schemas/Other"}`,
			to: `link: {$ref: "#/components/schemas/Other"}
        loose: {const: a}`,
			want: []string{"/components/schemas/Thing/properties/loose: a Schema Object with enum/const and no `type`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := textOriginBase
			if tc.name == "operator text in the request of a component a participant operation reaches by $ref" {
				doc = mutateOnce(t, doc, "  parameters:\n    Id:", "  parameters:\n    Opr:\n      in: query\n      name: o\n      schema: {type: string, x-ctf-text-origin: operator}\n    Id:")
			}
			rep := specFromYAML(t, mutateOnce(t, doc, tc.from, tc.to)).TextOrigin()
			if len(rep.Violations) == 0 {
				t.Fatalf("the mutation was not detected (a gate that cannot go red is not a gate)")
			}
			all := strings.Join(rep.Violations, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("violations do not contain %q; got:\n%s", w, all)
				}
			}
		})
	}
}

// TestTextOrigin_StaticRules_AllowedShapes: the same words are fine where
// ADR-0039 D2 allows them, so the rules above are not just "always red".
func TestTextOrigin_StaticRules_AllowedShapes(t *testing.T) {
	const noteOperator = `note: {type: string, x-ctf-text-origin: operator}`
	cases := []struct {
		name string
		edit func(doc string) string
		ok   bool
	}{
		{"operator in the request of an operator-audience operation", func(d string) string {
			d = mutateOnce(t, d, "    post:\n      parameters:", "    post:\n      x-ctf-audience: operator\n      parameters:")
			return mutateOnce(t, d, `note: {type: string, x-ctf-text-origin: participant-block}`, noteOperator)
		}, true},
		{"operator in the request of an internal operation the collector does not forward", func(d string) string {
			d = mutateOnce(t, d, "    post:\n      parameters:", "    post:\n      x-ctf-audience: internal\n      x-ctf-collector-forward: false\n      parameters:")
			return mutateOnce(t, d, `note: {type: string, x-ctf-text-origin: participant-block}`, noteOperator)
		}, true},
		{"operator in the request of an internal operation the collector forwards", func(d string) string {
			d = mutateOnce(t, d, "    post:\n      parameters:", "    post:\n      x-ctf-audience: internal\n      x-ctf-collector-forward: true\n      parameters:")
			return mutateOnce(t, d, `note: {type: string, x-ctf-text-origin: participant-block}`, noteOperator)
		}, false},
		{"operator in the request of an internal operation with no forward flag (fail-closed)", func(d string) string {
			d = mutateOnce(t, d, "    post:\n      parameters:", "    post:\n      x-ctf-audience: internal\n      parameters:")
			return mutateOnce(t, d, `note: {type: string, x-ctf-text-origin: participant-block}`, noteOperator)
		}, false},
		{"participant-opaque in a component no operation reaches", func(d string) string { return d }, true},
		{"a participant-inline named property used by two response schemas", func(d string) string {
			return mutateOnce(t, d, `link: {$ref: "#/components/schemas/Other"}`, `link: {$ref: "#/components/schemas/Other"}
        other:
          type: object
          properties:
            name: {type: string, x-ctf-text-origin: participant-inline}`)
		}, true},
		{"a recursive schema does not hang the walk", func(d string) string {
			return mutateOnce(t, d, `link: {$ref: "#/components/schemas/Other"}`, `link: {$ref: "#/components/schemas/Other"}
        self: {$ref: "#/components/schemas/Thing"}`)
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := specFromYAML(t, tc.edit(textOriginBase)).TextOrigin()
			if tc.ok && len(rep.Violations) != 0 {
				t.Fatalf("must be clean, got:\n%s", strings.Join(rep.Violations, "\n"))
			}
			if !tc.ok && len(rep.Violations) == 0 {
				t.Fatal("must be a violation, got none")
			}
		})
	}
}
