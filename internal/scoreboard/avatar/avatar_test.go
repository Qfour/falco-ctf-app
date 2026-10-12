package avatar

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestTable_FortyEightDistinctIDsInContractOrder(t *testing.T) {
	all := IDs()
	if len(all) != 48 {
		t.Fatalf("len(IDs()) = %d, want 48", len(all))
	}
	seen := map[string]bool{}
	for _, id := range all {
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
	if all[0] != "falcon-cyan" || all[47] != "flame-slate" {
		t.Fatalf("order: first=%q last=%q, want falcon-cyan .. flame-slate (glyph outer x colour inner)", all[0], all[47])
	}
	// glyph outer, colour inner: the second id keeps the glyph and moves the colour.
	if all[1] != "falcon-magenta" || all[6] != "shield-cyan" {
		t.Fatalf("axis order: [1]=%q [6]=%q, want falcon-magenta / shield-cyan", all[1], all[6])
	}
	if got := Number("falcon-cyan"); got != 1 {
		t.Fatalf("Number(falcon-cyan) = %d, want 1", got)
	}
	if got := Number("flame-slate"); got != 48 {
		t.Fatalf("Number(flame-slate) = %d, want 48", got)
	}
	if got := Number("nope-cyan"); got != 0 {
		t.Fatalf("Number(unknown) = %d, want 0", got)
	}
}

func TestGlyphAndColorNames_AreCopiesInTableOrder(t *testing.T) {
	g, c := GlyphNames(), ColorNames()
	if len(g) != 8 || len(c) != 6 || g[0] != "falcon" || g[7] != "flame" || c[0] != "cyan" || c[5] != "slate" {
		t.Fatalf("GlyphNames=%v ColorNames=%v", g, c)
	}
	g[0], c[0] = "x", "y"
	if GlyphNames()[0] != "falcon" || ColorNames()[0] != "cyan" {
		t.Fatal("mutating the returned slices changed the table")
	}
	// every id is exactly glyph-color from the two lists.
	want := map[string]bool{}
	for _, gg := range GlyphNames() {
		for _, cc := range ColorNames() {
			want[gg+"-"+cc] = true
		}
	}
	for _, id := range IDs() {
		if !want[id] {
			t.Fatalf("id %q is not <glyph>-<color> from GlyphNames x ColorNames", id)
		}
	}
}

func TestIDs_ReturnsACopy(t *testing.T) {
	a := IDs()
	a[0] = "tampered"
	if IDs()[0] != "falcon-cyan" {
		t.Fatal("mutating IDs()'s result changed the table")
	}
}

func TestValid(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"falcon-cyan", true},
		{"flame-slate", true},
		{StaffID, true},
		{"", false},
		{"falcon", false},
		{"cyan", false},
		{"falcon-red", false},
		{"Falcon-cyan", false},
		{"falcon-cyan ", false},
		{"falcon-cyan.svg", false},
		{"../falcon-cyan", false},
		{"falcon-cyan-cyan", false},
	} {
		if got := Valid(tc.id); got != tc.want {
			t.Errorf("Valid(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestFileAndColorToken_CoverTheWholeTable(t *testing.T) {
	files, tokens := map[string]bool{}, map[string]bool{}
	for _, id := range IDs() {
		f, ok := File(id)
		if !ok || !strings.HasSuffix(f, ".svg") || strings.ContainsAny(f, "/\\") {
			t.Fatalf("File(%q) = %q, %v", id, f, ok)
		}
		tok, ok := ColorToken(id)
		if !ok || !strings.HasPrefix(tok, "--avatar-") {
			t.Fatalf("ColorToken(%q) = %q, %v", id, tok, ok)
		}
		files[f], tokens[tok] = true, true
	}
	if len(files) != 8 || len(tokens) != 6 {
		t.Fatalf("distinct files = %d, tokens = %d, want 8 and 6 (colour is a token, not a file)", len(files), len(tokens))
	}
	if f, _ := File("falcon-cyan"); f != "falcon.svg" {
		t.Errorf("File(falcon-cyan) = %q, want falcon.svg", f)
	}
	if tok, _ := ColorToken("falcon-cyan"); tok != "--avatar-cyan" {
		t.Errorf("ColorToken(falcon-cyan) = %q, want --avatar-cyan", tok)
	}
	if _, ok := File("nope"); ok {
		t.Error("File accepted an id outside the table")
	}
	if _, ok := ColorToken("nope"); ok {
		t.Error("ColorToken accepted an id outside the table")
	}
}

func TestDefault_NumberedSeatsAreDistinctAndOrdered(t *testing.T) {
	all := IDs()
	seen := map[string]string{}
	for n := 1; n <= SeatCapacity; n++ {
		seat := fmt.Sprintf("user%d", n)
		got := Default(seat)
		if got != all[n-1] {
			t.Fatalf("Default(%s) = %q, want the %d-th id %q", seat, got, n, all[n-1])
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("Default(%s) = %q collides with %s", seat, got, prev)
		}
		seen[got] = seat
	}
}

func TestDefault_ReservedRange(t *testing.T) {
	all := IDs()
	// A seat that never chose lands on the 41st..47th; the 48th is StaffID's.
	reserved := map[string]bool{}
	for _, id := range all[SeatCapacity : Count-1] {
		reserved[id] = true
	}
	if len(reserved) != ParticipantReservedCount || ParticipantReservedCount != ReservedCount-1 {
		t.Fatalf("participant reserved tail = %d ids, want %d", len(reserved), ParticipantReservedCount)
	}
	for _, seat := range []string{
		"test1", "user01", "user0", "user00", "user041", "user41", "user48", "user49", "user1000",
		"user99999999999999999999", "admin", "x", "User1", "user1 ", "",
	} {
		got := Default(seat)
		if !reserved[got] {
			t.Errorf("Default(%q) = %q (#%d), want one of the reserved 41st..47th ids", seat, got, Number(got))
		}
	}
	// the boundary: 40 is numbered, 41 is reserved.
	if Number(Default("user40")) != 40 {
		t.Errorf("user40 -> #%d, want #40", Number(Default("user40")))
	}
	if Number(Default("user41")) <= SeatCapacity {
		t.Errorf("user41 -> #%d, want the reserved range (41..48)", Number(Default("user41")))
	}
}

func TestDefault_StableAndDisjointFromNumberedSeats(t *testing.T) {
	// Stable across calls (a per-process random hash would fail the second
	// Open of a store, or a second replica).
	for _, seat := range []string{"test1", "user01", "user41"} {
		if a, b := Default(seat), Default(seat); a != b {
			t.Fatalf("Default(%q) not stable: %q vs %q", seat, a, b)
		}
	}
	// Pinned: a changed hash would silently re-skin every reserved seat.
	if got, want := Default("test1"), IDs()[40+int(fnv32a("test1")%7)]; got != want {
		t.Fatalf("Default(test1) = %q, want %q", got, want)
	}
	// Pinned strings: Default is derived on every read, so a change to the
	// table (appending included) re-skins seats that never chose. These make
	// such a change a visible test diff instead of a silent one (R2#7).
	for seat, want := range map[string]string{
		"user1":  "falcon-cyan",
		"user7":  "shield-cyan",
		"user40": "bug-lime",
		"test1":  "bug-slate",
		"user41": "flame-lime",
		"user01": "flame-lime",
	} {
		if got := Default(seat); got != want {
			t.Errorf("Default(%q) = %q, want the pinned %q", seat, got, want)
		}
	}
	// prod = N numbered seats + test1: test1 can never take a numbered seat's id.
	numbered := map[string]bool{}
	for n := 1; n <= SeatCapacity; n++ {
		numbered[Default(fmt.Sprintf("user%d", n))] = true
	}
	if numbered[Default("test1")] {
		t.Fatalf("test1 default %q collides with a numbered seat", Default("test1"))
	}
}

func TestResolve_UnknownStoredFallsBackToDefault(t *testing.T) {
	if got := Resolve("bug-slate", "user3"); got != "bug-slate" {
		t.Errorf("Resolve(valid) = %q, want the stored id", got)
	}
	for _, stored := range []string{"", "bogus", "falcon-red", "falcon-cyan.svg"} {
		if got, want := Resolve(stored, "user3"), IDs()[2]; got != want {
			t.Errorf("Resolve(%q, user3) = %q, want default %q", stored, got, want)
		}
	}
	if got := Resolve("bogus", "test1"); got != Default("test1") {
		t.Errorf("Resolve(bogus, test1) = %q, want %q", got, Default("test1"))
	}
}

func TestParse(t *testing.T) {
	g, c, ok := Parse("radar-lime")
	if !ok || g != "radar" || c != "lime" {
		t.Fatalf("Parse(radar-lime) = %q %q %v", g, c, ok)
	}
	if _, _, ok := Parse("radar"); ok {
		t.Fatal("Parse accepted a non-table id")
	}
}

// fnv32a is the test's own copy of the hash Default must use, so the pinned
// expectation above does not just call the code under test.
func fnv32a(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// StaffID is the 48th id: the last of the reserved tail, so no numbered seat
// (user1..user40) defaults to it (ADR-0034 D8; VP decision).
func TestStaffID_IsTheLastReservedID(t *testing.T) {
	if StaffID != "flame-slate" {
		t.Fatalf("StaffID = %q, want flame-slate", StaffID)
	}
	if n := Number(StaffID); n != Count {
		t.Fatalf("Number(StaffID) = %d, want %d (the last id)", n, Count)
	}
	if Number(StaffID) <= SeatCapacity {
		t.Fatalf("StaffID is inside the numbered-seat range (1..%d)", SeatCapacity)
	}
	for n := 1; n <= SeatCapacity; n++ {
		if Default("user"+strconv.Itoa(n)) == StaffID {
			t.Fatalf("user%d defaults to StaffID", n)
		}
	}
}

// The operator's fixed id is not a participant's: no seat shape defaults to it
// (numbered, out-of-range, malformed, and a large sweep of hashed names), it is
// not in the participant set, and it is not selectable (ADR-0034 D8).
func TestStaffID_IsNeverAParticipantsID(t *testing.T) {
	seats := []string{"test1", "user01", "user0", "user00", "user41", "user48", "user49", "user1000",
		"user99999999999999999999", "admin", "x", "User1", "user1 ", "", "ctf-admin", "staff", "operator"}
	for n := 1; n <= 2000; n++ {
		seats = append(seats, "user"+strconv.Itoa(n), "test"+strconv.Itoa(n), "u"+strconv.Itoa(n), "user0"+strconv.Itoa(n))
	}
	hit := map[string]bool{}
	for _, seat := range seats {
		got := Default(seat)
		if got == StaffID {
			t.Fatalf("Default(%q) = StaffID", seat)
		}
		if n := Number(got); n == 0 || n >= Count {
			t.Fatalf("Default(%q) = %q (#%d), want a participant id (1..%d)", seat, got, n, Count-1)
		}
		if !Selectable(got) {
			t.Fatalf("Default(%q) = %q is not Selectable", seat, got)
		}
		if n := Number(got); n > SeatCapacity {
			hit[got] = true
		}
	}
	// the hash reaches the whole 41st..47th range (a divisor that silently
	// shrank would leave ids unreachable).
	if len(hit) != ParticipantReservedCount {
		t.Errorf("hashed seats reached %d of the %d reserved participant ids: %v", len(hit), ParticipantReservedCount, hit)
	}
}

func TestParticipantIDs_AreTheTableWithoutStaffID(t *testing.T) {
	p := ParticipantIDs()
	if len(p) != ParticipantCount || ParticipantCount != Count-1 {
		t.Fatalf("len(ParticipantIDs()) = %d, want %d", len(p), Count-1)
	}
	all := IDs()
	for i, id := range p {
		if id == StaffID {
			t.Fatalf("ParticipantIDs() contains StaffID at %d", i)
		}
		if id != all[i] {
			t.Fatalf("ParticipantIDs()[%d] = %q, want the table's %q (same order, StaffID is last)", i, id, all[i])
		}
		if !Selectable(id) || !Valid(id) {
			t.Fatalf("%q from ParticipantIDs() is not Selectable/Valid", id)
		}
	}
	p[0] = "tampered"
	if ParticipantIDs()[0] != "falcon-cyan" {
		t.Fatal("mutating ParticipantIDs()'s result changed the table")
	}
}

func TestSelectable(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"falcon-cyan", true},
		{"bug-slate", true}, // the 47th: the last id a participant can hold
		{StaffID, false},    // in the table (Valid) but the operator's
		{"", false},
		{"nope-cyan", false},
		{"Flame-Slate", false},
		{"flame-slate ", false},
	} {
		if got := Selectable(tc.id); got != tc.want {
			t.Errorf("Selectable(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
	if !Valid(StaffID) {
		t.Error("StaffID must stay a Valid table id (board messages carry it)")
	}
}

func TestResolve_StoredStaffIDDegradesToTheDefault(t *testing.T) {
	// The profile API never writes it, but a hand-edited DB must not make a
	// participant look like the operator.
	if got, want := Resolve(StaffID, "user3"), Default("user3"); got != want {
		t.Errorf("Resolve(StaffID, user3) = %q, want the default %q", got, want)
	}
	if got := Resolve(StaffID, "test1"); got == StaffID {
		t.Errorf("Resolve(StaffID, test1) = StaffID")
	}
}
