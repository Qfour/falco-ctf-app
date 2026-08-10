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

func TestEnvInt(t *testing.T) {
	if got := EnvInt("SU_INT_MISSING", 7); got != 7 {
		t.Fatalf("unset → fallback: got %d", got)
	}
	t.Setenv("SU_INT_KEY", "42")
	if got := EnvInt("SU_INT_KEY", 7); got != 42 {
		t.Fatalf("valid: got %d", got)
	}
	t.Setenv("SU_INT_KEY", " 13 ")
	if got := EnvInt("SU_INT_KEY", 7); got != 13 {
		t.Fatalf("trimmed valid: got %d", got)
	}
	t.Setenv("SU_INT_KEY", "")
	if got := EnvInt("SU_INT_KEY", 7); got != 7 {
		t.Fatalf("empty → fallback: got %d", got)
	}
	t.Setenv("SU_INT_KEY", "notanumber")
	if got := EnvInt("SU_INT_KEY", 7); got != 7 {
		t.Fatalf("malformed → fallback: got %d", got)
	}
	t.Setenv("SU_INT_KEY", "-5")
	if got := EnvInt("SU_INT_KEY", 7); got != -5 {
		t.Fatalf("negative allowed (normalised later in scoring): got %d", got)
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
