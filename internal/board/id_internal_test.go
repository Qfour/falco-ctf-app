package board

import (
	"strings"
	"testing"
)

// ValidID is the shape of what newID generates (the same function makes thread
// and message ids): a generated id always passes, and near misses never do.
func TestValidID_AgreesWithNewID(t *testing.T) {
	for i := 0; i < 100; i++ {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidID(id) {
			t.Fatalf("a generated id %q is not ValidID", id)
		}
	}
	good, _ := newID()
	for name, bad := range map[string]string{
		"empty":     "",
		"short":     good[:len(good)-1],
		"long":      good + "a",
		"upper":     strings.ToUpper(good),
		"not hex":   strings.Repeat("g", len(good)),
		"newline":   good[:len(good)-1] + "\n",
		"bidi":      "\u202e" + good[:len(good)-1],
		"space pad": " " + good,
	} {
		if ValidID(bad) {
			t.Errorf("%s: %q passes ValidID", name, bad)
		}
	}
}
