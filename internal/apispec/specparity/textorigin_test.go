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

// withComponent adds a component entry (YAML text, already indented for its
// section) at the top of `section`.
func withComponent(t *testing.T, doc, section, entry string) string {
	t.Helper()
	return mutateOnce(t, doc, "\n  "+section+":\n", "\n  "+section+":\n"+entry)
}

// TestTextOrigin_StaticRules_Mutations is ADR-0039 V2's S1b half: each case
// breaks one rule between a word and where its node sits (or D3 (h), or a
// $ref shape) and must go red naming the pointer.
func TestTextOrigin_StaticRules_Mutations(t *testing.T) {
	const link = `link: {$ref: "#/components/schemas/Other"}`
	cases := []struct {
		name     string
		setup    func(t *testing.T, doc string) string // optional: extra components before the edit
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
			name: "participant-opaque reachable from a response through a chain of $ref aliases",
			setup: func(t *testing.T, d string) string {
				d = mutateOnce(t, d, `Other: {type: string, x-ctf-text-origin: operator}`, `Other: {type: string, x-ctf-text-origin: participant-opaque}`)
				return withComponent(t, d, "schemas", "    Alias2: {$ref: \"#/components/schemas/Other\"}\n    Alias: {$ref: \"#/components/schemas/Alias2\"}\n")
			},
			from: link, to: `link: {$ref: "#/components/schemas/Alias"}`,
			want: []string{"/components/schemas/Other: `participant-opaque` is reachable from a response"},
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
			setup: func(t *testing.T, d string) string {
				return withComponent(t, d, "parameters", "    Opr:\n      in: query\n      name: o\n      schema: {type: string, x-ctf-text-origin: operator}\n")
			},
			from: `- $ref: "#/components/parameters/Id"`, to: `- $ref: "#/components/parameters/Opr"`,
			want: []string{"/components/parameters/Opr/schema: `operator` text in the request of POST /a/{id}"},
		},
		{
			name: "operator text in a participant request through a chain of parameter aliases",
			setup: func(t *testing.T, d string) string {
				d = withComponent(t, d, "parameters", "    OprAlias: {$ref: \"#/components/parameters/Opr\"}\n")
				return withComponent(t, d, "parameters", "    Opr:\n      in: query\n      name: o\n      schema: {type: string, x-ctf-text-origin: operator}\n")
			},
			from: `- $ref: "#/components/parameters/Id"`, to: `- $ref: "#/components/parameters/OprAlias"`,
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
			name: "participant-inline in an array's items through a $ref alias",
			setup: func(t *testing.T, d string) string {
				d = mutateOnce(t, d, `Other: {type: string, x-ctf-text-origin: operator}`, `Other: {type: string, x-ctf-text-origin: participant-inline}`)
				return withComponent(t, d, "schemas", "    Alias: {$ref: \"#/components/schemas/Other\"}\n")
			},
			from: `items: {type: string, x-ctf-text-origin: operator}`, to: `items: {$ref: "#/components/schemas/Alias"}`,
			want: []string{`/components/schemas/Other: "participant-inline" in a response must be a named property`},
		},
		{
			name: "participant-inline in additionalProperties of a response",
			from: `additionalProperties: {type: string, x-ctf-text-origin: operator}`,
			to:   `additionalProperties: {type: string, x-ctf-text-origin: participant-block}`,
			want: []string{`/components/schemas/Thing/properties/extra/additionalProperties: "participant-block" in a response must be a named property`},
		},
		{
			name: "participant-inline in a combinator branch of a response property",
			from: `- {type: string, x-ctf-text-origin: token}
        either:`,
			to: `- {type: string, x-ctf-text-origin: participant-inline}
        either:`,
			want: []string{`/components/schemas/Thing/properties/both/allOf/0: "participant-inline" in a response must be a named property`},
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
			name: "participant-inline in a header whose NAME is `properties` is not read as a named property",
			from: `X-Out:
              schema: {type: string, x-ctf-text-origin: operator}`,
			to: `properties:
              schema: {type: string, x-ctf-text-origin: participant-inline}`,
			want: []string{`/paths/~1a~1{id}/post/responses/200/headers/properties/schema: "participant-inline" in a response must be a named property`},
		},
		{
			name: "a participant-* property name reused for an operator string in a response",
			from: link,
			to: link + `
        nested:
          type: object
          properties:
            name: {type: string, x-ctf-text-origin: operator}`,
			want: []string{
				`/components/schemas/Thing/properties/nested/properties/name: used from a response property named "name", which is a participant-text name there, but this node is declared operator`,
				`/components/schemas/Thing/properties/name: used from a response property named "name"`,
			},
		},
		{
			name: "a token component used from a participant-named property through a $ref (use-site name)",
			setup: func(t *testing.T, d string) string {
				return withComponent(t, d, "schemas", "    Tok: {type: string, x-ctf-text-origin: token}\n")
			},
			from: link,
			to: link + `
        nested:
          type: object
          properties:
            name: {$ref: "#/components/schemas/Tok"}`,
			want: []string{`/components/schemas/Tok: used from a response property named "name", which is a participant-text name there, but this node is declared token`},
		},
		{
			name: "a participant-inline component referenced through a $ref",
			setup: func(t *testing.T, d string) string {
				return mutateOnce(t, d, `Other: {type: string, x-ctf-text-origin: operator}`, `Other: {type: string, x-ctf-text-origin: participant-inline}`)
			},
			from: `x: x`, to: `x: x`, // no edit: the component is already referenced by `link`
			want: []string{`/components/schemas/Other: "participant-inline" is referenced through a ` + "`$ref`" + `; participant-inline / -block are written inline`},
		},
		{
			name: "a participant-block component referenced from a request",
			setup: func(t *testing.T, d string) string {
				d = withComponent(t, d, "parameters", "    Shared:\n      in: query\n      name: s\n      schema: {$ref: \"#/components/schemas/Blk\"}\n")
				return withComponent(t, d, "schemas", "    Blk: {type: string, x-ctf-text-origin: participant-block}\n")
			},
			from: `- $ref: "#/components/parameters/Id"`, to: `- $ref: "#/components/parameters/Shared"`,
			want: []string{`/components/schemas/Blk: "participant-block" is referenced through a ` + "`$ref`"},
		},
		{
			name: "a $ref with a sibling schema keyword",
			from: link,
			to:   `link: {$ref: "#/components/schemas/Other", nullable: true}`,
			want: []string{"/components/schemas/Thing/properties/link: a $ref with sibling keywords nullable"},
		},
		{
			name: "enum without type",
			from: link,
			to: link + `
        loose: {enum: [a, b]}`,
			want: []string{"/components/schemas/Thing/properties/loose: a Schema Object with enum/const and no `type`"},
		},
		{
			name: "const without type",
			from: link,
			to: link + `
        loose: {const: a}`,
			want: []string{"/components/schemas/Thing/properties/loose: a Schema Object with enum/const and no `type`"},
		},
		{
			name: "enum without type in a position the walk does not descend (not:)",
			from: link,
			to: link + `
        constrained:
          type: object
          not: {enum: [a, b]}`,
			want: []string{"/components/schemas/Thing/properties/constrained/not: a Schema Object with enum/const and no `type`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := textOriginBase
			if tc.setup != nil {
				doc = tc.setup(t, doc)
			}
			if tc.from != "x: x" {
				doc = mutateOnce(t, doc, tc.from, tc.to)
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

// TestTextOrigin_StaticRules_AllowedShapes: the same words are fine where
// ADR-0039 D2 allows them, so the rules above are not just "always red". A
// case that must fail names the part of the violation text it must carry.
func TestTextOrigin_StaticRules_AllowedShapes(t *testing.T) {
	const link = `link: {$ref: "#/components/schemas/Other"}`
	const noteOperator = `note: {type: string, x-ctf-text-origin: operator}`
	const noteBlock = `note: {type: string, x-ctf-text-origin: participant-block}`
	postOps := func(t *testing.T, d, ext string) string {
		return mutateOnce(t, d, "    post:\n      parameters:", "    post:\n"+ext+"      parameters:")
	}
	cases := []struct {
		name    string
		edit    func(t *testing.T, doc string) string
		wantSub string // "" = must be clean
	}{
		{"operator in the request of an operator-audience operation the collector does not forward", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: operator\n      x-ctf-collector-forward: false\n"), noteBlock, noteOperator)
		}, ""},
		{"operator in the request of an operator-audience operation with no forward flag (fail-closed)", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: operator\n"), noteBlock, noteOperator)
		}, "properties/note: `operator` text in the request of POST /a/{id}"},
		{"operator in the request of an operator-audience operation the collector forwards", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: operator\n      x-ctf-collector-forward: true\n"), noteBlock, noteOperator)
		}, "properties/note: `operator` text in the request of POST /a/{id}"},
		{"operator in the request of an internal operation the collector does not forward", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: internal\n      x-ctf-collector-forward: false\n"), noteBlock, noteOperator)
		}, ""},
		{"operator in the request of an internal operation the collector forwards", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: internal\n      x-ctf-collector-forward: true\n"), noteBlock, noteOperator)
		}, "properties/note: `operator` text in the request of POST /a/{id}"},
		{"operator in the request of an internal operation with no forward flag (fail-closed)", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: internal\n"), noteBlock, noteOperator)
		}, "properties/note: `operator` text in the request of POST /a/{id}"},
		{"operator in the request of a participant-audience operation", func(t *testing.T, d string) string {
			return mutateOnce(t, postOps(t, d, "      x-ctf-audience: participant\n      x-ctf-collector-forward: false\n"), noteBlock, noteOperator)
		}, "properties/note: `operator` text in the request of POST /a/{id}"},
		{"operator in a path-item level parameter of a participant operation", func(t *testing.T, d string) string {
			return mutateOnce(t, d, `schema: {type: string, x-ctf-text-origin: participant-opaque}
    post:`, `schema: {type: string, x-ctf-text-origin: operator}
    post:`)
		}, "/paths/~1a~1{id}/parameters/0/schema: `operator` text in the request of POST /a/{id}"},
		{"participant-opaque in a component no operation reaches", func(t *testing.T, d string) string { return d }, ""},
		{"a component reached from both a request and a response is judged on both sides", func(t *testing.T, d string) string {
			d = withComponent(t, d, "schemas", "    Both: {type: string, x-ctf-text-origin: operator}\n")
			d = mutateOnce(t, d, link, link+"\n        both2: {$ref: \"#/components/schemas/Both\"}")
			return mutateOnce(t, d, `- $ref: "#/components/parameters/Id"`, `- {in: query, name: b, schema: {$ref: "#/components/schemas/Both"}}`)
		}, "/components/schemas/Both: `operator` text in the request of POST /a/{id}"},
		{"a string reached only through components.responses and components.requestBodies is walked", func(t *testing.T, d string) string {
			d = mutateOnce(t, d, `"200":
          description: ok`, `"200": {$ref: "#/components/responses/Gone"}
        "201":
          description: ok`)
			return mutateOnce(t, d, `x-ctf-text-origin: operator}
  requestBodies:`, `x-ctf-text-origin: participant-opaque}
  requestBodies:`)
		}, "/components/responses/Gone/content/text~1plain/schema: `participant-opaque` is reachable from a response"},
		{"a participant-inline named property used by two response schemas", func(t *testing.T, d string) string {
			return mutateOnce(t, d, link, link+`
        other:
          type: object
          properties:
            name: {type: string, x-ctf-text-origin: participant-inline}`)
		}, ""},
		{"a $ref with only a description beside it", func(t *testing.T, d string) string {
			return mutateOnce(t, d, link, `link: {$ref: "#/components/schemas/Other", description: shared}`)
		}, ""},
		{"a property merely NAMED enum or const is no keyword", func(t *testing.T, d string) string {
			return mutateOnce(t, d, link, link+`
        enum: {type: string, x-ctf-text-origin: operator}
        const: {type: string, x-ctf-text-origin: operator}`)
		}, ""},
		{"a recursive schema does not hang the walk", func(t *testing.T, d string) string {
			return mutateOnce(t, d, link, link+`
        self: {$ref: "#/components/schemas/Thing"}`)
		}, ""},
		{"a $ref cycle holds no string and does not hang the walk", func(t *testing.T, d string) string {
			d = withComponent(t, d, "schemas", "    CycA: {$ref: \"#/components/schemas/CycB\"}\n    CycB: {$ref: \"#/components/schemas/CycA\"}\n")
			return mutateOnce(t, d, link, link+"\n        cyc: {$ref: \"#/components/schemas/CycA\"}")
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := specFromYAML(t, tc.edit(t, textOriginBase)).TextOrigin()
			all := strings.Join(rep.Violations, "\n")
			switch {
			case tc.wantSub == "" && len(rep.Violations) != 0:
				t.Fatalf("must be clean, got:\n%s", all)
			case tc.wantSub != "" && len(rep.Violations) == 0:
				t.Fatalf("must be a violation containing %q, got none", tc.wantSub)
			case tc.wantSub != "" && !strings.Contains(all, tc.wantSub):
				t.Fatalf("violation does not contain %q; got:\n%s", tc.wantSub, all)
			}
		})
	}
}

// TestInlineNodesNotReached proves the two-walk invariant is checkable: the
// real walk and the reachability walk agree on the base document, and a
// node the reachability walk never visited is reported.
func TestInlineNodesNotReached(t *testing.T) {
	s := specFromYAML(t, textOriginBase)
	nodes := s.walkSchemas().nodes
	rs := s.reachability()
	if got := inlineNodesNotReached(nodes, rs); len(got) != 0 {
		t.Fatalf("the walks disagree on the base document: %v", got)
	}
	inline := 0
	for _, n := range nodes {
		if strings.HasPrefix(n.Pointer, "/paths/") {
			inline++
		}
	}
	if inline == 0 {
		t.Fatal("no inline node under /paths/ in the base document: the invariant would be vacuous")
	}
	fake := append([]StringNode{{Pointer: "/paths/~1x/get/parameters/0/schema"}}, nodes...)
	got := inlineNodesNotReached(fake, rs)
	if len(got) != 1 || got[0] != "/paths/~1x/get/parameters/0/schema" {
		t.Fatalf("a node outside the reachability walk must be reported, got %v", got)
	}
}

const forwardTarget = `
openapi: 3.1.0
paths:
  /internal/x/{cid}:
    post:
      x-ctf-audience: internal
      x-ctf-collector-forward: false
      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Req"}
components:
  schemas:
    Req:
      type: object
      required: [user, flag]
      properties:
        user: {type: string, pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
        flag: {type: string, x-ctf-text-origin: participant-opaque}
`

const forwardCopy = `
openapi: 3.1.0
paths:
  /api/x/{cid}:
    post:
      x-ctf-audience: participant
      x-ctf-collector-forward: true
      x-ctf-forward-target: "POST /internal/x/{cid}"
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [user, flag]
              properties:
                user: {type: string, pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag: {type: string, x-ctf-text-origin: participant-opaque}
`

func TestCollectorCopy_BaselineAgrees(t *testing.T) {
	v, n := CollectorCopyViolations(specFromYAML(t, forwardCopy), specFromYAML(t, forwardTarget))
	if len(v) != 0 {
		t.Fatalf("baseline must agree, got:\n%s", strings.Join(v, "\n"))
	}
	if n != 2 {
		t.Fatalf("compared %d string nodes, want 2 (user, flag): a comparison of 0 is not agreement", n)
	}
}

// TestCollectorCopy_Mutations: ADR-0039 V2's collector rows, one change to the
// copy (or the target) each.
func TestCollectorCopy_Mutations(t *testing.T) {
	cases := []struct {
		name     string
		onTarget bool // mutate the target instead of the copy
		from, to string
		want     []string
	}{
		{"the copy's class differs from the target's", false,
			`flag: {type: string, x-ctf-text-origin: participant-opaque}`, `flag: {type: string, x-ctf-text-origin: operator}`,
			[]string{"requestBody/properties/flag vs POST /internal/x/{cid}: x-ctf-text-origin differs: copy operator, target participant-opaque"}},
		{"the copy's pattern differs by one character", false,
			`pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag`, `pattern: '^[a-y]+$', maxLength: 63, x-ctf-text-origin: token}
                flag`,
			[]string{"properties/user vs POST /internal/x/{cid}: pattern differs"}},
		{"the copy's pattern is missing", false,
			`pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag`, `maxLength: 63, x-ctf-text-origin: token}
                flag`,
			[]string{"pattern differs: copy (absent), target ^[a-z]+$"}},
		{"the copy's maxLength is missing", false,
			`pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag`, `pattern: '^[a-z]+$', x-ctf-text-origin: token}
                flag`,
			[]string{"maxLength differs: copy (absent), target 63"}},
		{"the copy's required drops flag", false,
			`required: [user, flag]
              properties:`, `required: [user]
              properties:`,
			[]string{"properties/flag vs POST /internal/x/{cid}: required differs: copy false, target true"}},
		{"the copy gains a minLength", false,
			`maxLength: 63, x-ctf-text-origin: token}
                flag`, `maxLength: 63, minLength: 1, x-ctf-text-origin: token}
                flag`,
			[]string{"minLength differs: copy 1, target (absent)"}},
		{"the copy gains a format", false,
			`flag: {type: string, x-ctf-text-origin: participant-opaque}`, `flag: {type: string, format: byte, x-ctf-text-origin: participant-opaque}`,
			[]string{"properties/flag vs POST /internal/x/{cid}: format differs"}},
		{"the copy gains a string property the target lacks", false,
			`flag: {type: string, x-ctf-text-origin: participant-opaque}`, `flag: {type: string, x-ctf-text-origin: participant-opaque}
                extra: {type: string, x-ctf-text-origin: participant-opaque}`,
			[]string{"properties/extra vs POST /internal/x/{cid}: the copy has a string node the target does not"}},
		{"the target gains a string property the copy lacks", true,
			`flag: {type: string, x-ctf-text-origin: participant-opaque}`, `flag: {type: string, x-ctf-text-origin: participant-opaque}
        more: {type: string, x-ctf-text-origin: token}`,
			[]string{"properties/more vs POST /internal/x/{cid}: the target has a string node the copy lacks"}},
		{"the target's maxLength changes", true,
			`maxLength: 63`, `maxLength: 64`,
			[]string{"maxLength differs: copy 63, target 64"}},
		{"the forward target names no operation", false,
			`x-ctf-forward-target: "POST /internal/x/{cid}"`, `x-ctf-forward-target: "POST /internal/y/{cid}"`,
			[]string{`x-ctf-forward-target "POST /internal/y/{cid}" is not an operation of the target spec`}},
		{"the forward target is missing", false,
			`      x-ctf-forward-target: "POST /internal/x/{cid}"
`, ``,
			[]string{"writes a request schema but has no x-ctf-forward-target"}},
		{"the copy $refs outside the document", false,
			`schema:
              type: object
              required: [user, flag]
              properties:
                user: {type: string, pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag: {type: string, x-ctf-text-origin: participant-opaque}`, `schema: {$ref: "scoreboard.yaml#/components/schemas/Req"}`,
			[]string{`$ref "scoreboard.yaml#/components/schemas/Req" does not name an existing`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdoc, tdoc := forwardCopy, forwardTarget
			if tc.onTarget {
				tdoc = mutateOnce(t, tdoc, tc.from, tc.to)
			} else {
				cdoc = mutateOnce(t, cdoc, tc.from, tc.to)
			}
			v, _ := CollectorCopyViolations(specFromYAML(t, cdoc), specFromYAML(t, tdoc))
			if len(v) == 0 {
				t.Fatal("the mutation was not detected")
			}
			all := strings.Join(v, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("violations do not contain %q; got:\n%s", w, all)
				}
			}
		})
	}
}

// TestCollectorCopy_NoSchemaWrittenIsNothingToCompare: a forwarded operation
// whose body is "{}" (submit) is skipped, and a spec with no comparable copy at
// all reports compared == 0 so the real-spec test can refuse that.
func TestCollectorCopy_NoSchemaWrittenIsNothingToCompare(t *testing.T) {
	doc := mutateOnce(t, forwardCopy, `            schema:
              type: object
              required: [user, flag]
              properties:
                user: {type: string, pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag: {type: string, x-ctf-text-origin: participant-opaque}`, `            {}`)
	v, n := CollectorCopyViolations(specFromYAML(t, doc), specFromYAML(t, forwardTarget))
	if len(v) != 0 || n != 0 {
		t.Fatalf("got violations %v, compared %d; want none and 0", v, n)
	}
}

// copyBodyInline is forwardCopy's request schema, as written in the base.
const copyBodyInline = `            schema:
              type: object
              required: [user, flag]
              properties:
                user: {type: string, pattern: '^[a-z]+$', maxLength: 63, x-ctf-text-origin: token}
                flag: {type: string, x-ctf-text-origin: participant-opaque}`

// copyWithRequestBodyComponent moves the copy's whole requestBody into
// components.requestBodies and points the operation at it with a $ref.
func copyWithRequestBodyComponent(t *testing.T) string {
	t.Helper()
	d := mutateOnce(t, forwardCopy, `      requestBody:
        content:
          application/json:
`+copyBodyInline, `      requestBody: {$ref: "#/components/requestBodies/ExfilBody"}`)
	return d + `components:
  requestBodies:
    ExfilBody:
      content:
        application/json:
` + copyBodyInline + "\n"
}

// TestCollectorCopy_RequestBodyRef: a request body that is a $ref to
// components.requestBodies is resolved before it is read, on either side (a
// copy hidden behind one must not read as "nothing to compare").
func TestCollectorCopy_RequestBodyRef(t *testing.T) {
	t.Run("the copy behind a requestBodies $ref is compared", func(t *testing.T) {
		v, n := CollectorCopyViolations(specFromYAML(t, copyWithRequestBodyComponent(t)), specFromYAML(t, forwardTarget))
		if len(v) != 0 || n != 2 {
			t.Fatalf("want clean and 2 compared, got %d compared, violations:\n%s", n, strings.Join(v, "\n"))
		}
	})
	t.Run("a pattern difference behind a requestBodies $ref is caught", func(t *testing.T) {
		d := mutateOnce(t, copyWithRequestBodyComponent(t), `pattern: '^[a-z]+$'`, `pattern: '^[a-y]+$'`)
		v, _ := CollectorCopyViolations(specFromYAML(t, d), specFromYAML(t, forwardTarget))
		if !strings.Contains(strings.Join(v, "\n"), "properties/user vs POST /internal/x/{cid}: pattern differs") {
			t.Fatalf("not caught, got:\n%s", strings.Join(v, "\n"))
		}
	})
	t.Run("the target behind a requestBodies $ref is compared", func(t *testing.T) {
		tgt := mutateOnce(t, forwardTarget, `      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Req"}`, `      requestBody: {$ref: "#/components/requestBodies/TBody"}`)
		tgt += `  requestBodies:
    TBody:
      content:
        application/json:
          schema: {$ref: "#/components/schemas/Req"}
`
		v, n := CollectorCopyViolations(specFromYAML(t, forwardCopy), specFromYAML(t, tgt))
		if len(v) != 0 || n != 2 {
			t.Fatalf("want clean and 2 compared, got %d compared, violations:\n%s", n, strings.Join(v, "\n"))
		}
	})
	t.Run("an unresolvable requestBody $ref is a violation, not a skip", func(t *testing.T) {
		d := mutateOnce(t, forwardCopy, `      requestBody:
        content:
          application/json:
`+copyBodyInline, `      requestBody: {$ref: "#/components/requestBodies/Nope"}`)
		v, _ := CollectorCopyViolations(specFromYAML(t, d), specFromYAML(t, forwardTarget))
		if !strings.Contains(strings.Join(v, "\n"), "its requestBody is not readable") {
			t.Fatalf("got:\n%s", strings.Join(v, "\n"))
		}
	})
	t.Run("a schema written only under another media type is a violation", func(t *testing.T) {
		d := mutateOnce(t, forwardCopy, "application/json:\n"+copyBodyInline, "text/plain:\n"+copyBodyInline)
		v, _ := CollectorCopyViolations(specFromYAML(t, d), specFromYAML(t, forwardTarget))
		if !strings.Contains(strings.Join(v, "\n"), "only under text/plain, not application/json") {
			t.Fatalf("got:\n%s", strings.Join(v, "\n"))
		}
	})
	t.Run("a target with no request schema is a violation", func(t *testing.T) {
		tgt := mutateOnce(t, forwardTarget, `      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Req"}
`, ``)
		v, _ := CollectorCopyViolations(specFromYAML(t, forwardCopy), specFromYAML(t, tgt))
		if !strings.Contains(strings.Join(v, "\n"), "has no application/json request schema") {
			t.Fatalf("got:\n%s", strings.Join(v, "\n"))
		}
	})
	t.Run("a target whose body cannot be read is a violation naming the target", func(t *testing.T) {
		tgt := mutateOnce(t, forwardTarget, `      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Req"}`, `      requestBody: {$ref: "#/components/requestBodies/Nope"}`)
		v, _ := CollectorCopyViolations(specFromYAML(t, forwardCopy), specFromYAML(t, tgt))
		if !strings.Contains(strings.Join(v, "\n"), "its target POST /internal/x/{cid}: its requestBody is not readable") {
			t.Fatalf("got:\n%s", strings.Join(v, "\n"))
		}
	})
	t.Run("a recursive $ref in the copy is a violation, not a hang", func(t *testing.T) {
		d := mutateOnce(t, forwardCopy, copyBodyInline, `            schema: {$ref: "#/components/schemas/Rec"}`) + `components:
  schemas:
    Rec:
      type: object
      properties:
        self: {$ref: "#/components/schemas/Rec"}
`
		v, _ := CollectorCopyViolations(specFromYAML(t, d), specFromYAML(t, forwardTarget))
		if !strings.Contains(strings.Join(v, "\n"), "recursive $ref") {
			t.Fatalf("got:\n%s", strings.Join(v, "\n"))
		}
	})
}
