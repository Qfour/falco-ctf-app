package serverutil

import (
	"reflect"
	"testing"
)

func TestEnv(t *testing.T) {
	t.Setenv("SU_TEST_KEY", "v")
	if got := Env("SU_TEST_KEY", "fb"); got != "v" {
		t.Fatalf("set: got %q", got)
	}
	t.Setenv("SU_TEST_KEY", "")
	if got := Env("SU_TEST_KEY", "fb"); got != "fb" {
		t.Fatalf("empty → fallback: got %q", got)
	}
	if got := Env("SU_TEST_MISSING", "fb"); got != "fb" {
		t.Fatalf("unset → fallback: got %q", got)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{" a , b ,, c ", []string{"a", "b", "c"}},
		{" , ", nil},
	}
	for _, c := range cases {
		if got := SplitCSV(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitCSV(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
