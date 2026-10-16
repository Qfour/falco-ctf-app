package scoreboard_test

// ADR-0034 S1 spec-level checks that the generic parity tests cannot express:
// the spec's AvatarId enum IS the Go table; no operation takes an image body
// (V2, condition 9); the profile schemas hold exactly the allowed fields; and
// every response shape ADR-0034 D8 names carries `avatar` / `authorAvatar` as
// a required AvatarId.

import (
	"sort"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/apispec/specparity"
	"github.com/Qfour/falco-ctf-app/internal/scoreboard/avatar"
)

func schemaProps(t *testing.T, spec *specparity.Spec, name string) map[string]any {
	t.Helper()
	sch := spec.SchemaByName(name)
	if sch == nil {
		t.Fatalf("spec has no components.schemas.%s", name)
	}
	props, _ := sch["properties"].(map[string]any)
	if len(props) == 0 {
		t.Fatalf("components.schemas.%s has no properties", name)
	}
	return props
}

func requiredSet(sch map[string]any) map[string]bool {
	out := map[string]bool{}
	req, _ := sch["required"].([]any)
	for _, r := range req {
		if s, ok := r.(string); ok {
			out[s] = true
		}
	}
	return out
}

func TestProfileSpec_AvatarIdEnumIsTheGoTable(t *testing.T) {
	spec := loadScoreboardSpec(t)
	sch := spec.SchemaByName("AvatarId")
	if sch == nil {
		t.Fatal("spec has no components.schemas.AvatarId")
	}
	raw, _ := sch["enum"].([]any)
	var got []string
	for _, v := range raw {
		s, _ := v.(string)
		got = append(got, s)
	}
	want := avatar.IDs()
	if len(got) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("spec AvatarId.enum != avatar.IDs() (same ids, same order):\n spec: %v\n  go: %v", got, want)
	}
}

// V2: no operation in the spec takes (or documents) an image / multipart /
// octet-stream request body — a participant never uploads anything (ADR-0034
// conditions 8 and 9).
func TestProfileSpec_V2_NoUploadRequestBodiesAnywhere(t *testing.T) {
	spec := loadScoreboardSpec(t)
	ops := spec.Operations()
	if len(ops) == 0 {
		t.Fatal("spec parsed to zero operations — loading is broken, not clean")
	}
	var withBody int
	for key, op := range ops {
		rb, _ := op["requestBody"].(map[string]any)
		if rb == nil {
			continue
		}
		withBody++
		content, _ := rb["content"].(map[string]any)
		for mt := range content {
			m := strings.ToLower(mt)
			if strings.HasPrefix(m, "image/") || strings.HasPrefix(m, "multipart/") || m == "application/octet-stream" {
				t.Errorf("%s declares a %s request body — uploads are out of scope (ADR-0034 V2)", key, mt)
			}
		}
	}
	if withBody < 5 {
		t.Fatalf("only %d operations declare a request body — the walk is broken, not clean", withBody)
	}
}

func TestProfileSpec_V7_ProfileSchemasHoldOnlyTheAllowedFields(t *testing.T) {
	spec := loadScoreboardSpec(t)
	keys := func(m map[string]any) string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	if got := keys(schemaProps(t, spec, "ProfileRequest")); got != "avatar,display_name" {
		t.Fatalf("ProfileRequest properties = %s, want exactly avatar,display_name", got)
	}
	if got := keys(schemaProps(t, spec, "ProfileResult")); got != "avatar,display_name,ok,user" {
		t.Fatalf("ProfileResult properties = %s, want exactly avatar,display_name,ok,user", got)
	}
	// An unknown key is rejected by the handler, so the spec must say so.
	if ap, ok := spec.SchemaByName("ProfileRequest")["additionalProperties"].(bool); !ok || ap {
		t.Fatal("ProfileRequest must declare additionalProperties: false")
	}
	if mp, _ := spec.SchemaByName("ProfileRequest")["minProperties"].(int); mp != 1 {
		// yaml decoders differ on the number type; accept float64 too.
		if f, _ := spec.SchemaByName("ProfileRequest")["minProperties"].(float64); f != 1 {
			t.Fatalf("ProfileRequest.minProperties = %v, want 1", spec.SchemaByName("ProfileRequest")["minProperties"])
		}
	}
	// ProfileRequest must not be anything a client could put an image in.
	for name, p := range schemaProps(t, spec, "ProfileRequest") {
		pm, _ := p.(map[string]any)
		if f, _ := pm["format"].(string); f == "binary" || f == "byte" {
			t.Errorf("ProfileRequest.%s has format %s", name, f)
		}
	}
}

// The additive `avatar` fields (D8): a required AvatarId on each shape that
// carries a display name, `authorAvatar` on BoardMessage.
func TestProfileSpec_AvatarFieldsAreRequiredAvatarIdRefs(t *testing.T) {
	spec := loadScoreboardSpec(t)
	for _, tc := range []struct{ schema, field string }{
		{"Me", "avatar"},
		{"Journey", "avatar"},
		{"LeaderboardEntry", "avatar"},
		{"ChallengeSolver", "avatar"},
		{"SolveRecord", "avatar"},
		{"BoardMessage", "authorAvatar"},
		{"ProfileResult", "avatar"},
	} {
		t.Run(tc.schema+"."+tc.field, func(t *testing.T) {
			props := schemaProps(t, spec, tc.schema)
			p, ok := props[tc.field].(map[string]any)
			if !ok {
				t.Fatalf("%s has no property %s", tc.schema, tc.field)
			}
			if ref, _ := p["$ref"].(string); ref != "#/components/schemas/AvatarId" {
				t.Fatalf("%s.%s = %v, want a $ref to AvatarId", tc.schema, tc.field, p)
			}
			if !requiredSet(spec.SchemaByName(tc.schema))[tc.field] {
				t.Fatalf("%s.%s must be required (always present; unset reads as the default id)", tc.schema, tc.field)
			}
		})
	}
}
