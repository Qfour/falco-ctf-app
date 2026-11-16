package edition_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Qfour/falco-ctf-app/internal/edition"
)

func TestParse_Valid(t *testing.T) {
	tb := mustParse(t, render(runA, baseRows()))
	if got := tb.RunID(); got != runA {
		t.Errorf("RunID = %q, want %q", got, runA)
	}
	if got, want := tb.Seats(), []string{"seat-a", "seat-b"}; !slices.Equal(got, want) {
		t.Errorf("Seats = %v, want %v", got, want)
	}
}

func TestPracticeRunID_IsThirtyTwoZeros(t *testing.T) {
	if edition.PracticeRunID != strings.Repeat("0", 32) {
		t.Errorf("PracticeRunID = %q", edition.PracticeRunID)
	}
}

// ADR-0056 D10 T3 (and the duplicate row of T4): one defect per case. line 0 =
// the defect is not on a line.
func TestParse_Rejects(t *testing.T) {
	full := render(runA, baseRows())
	cases := []struct {
		name string
		data []byte
		rule string
		line int
	}{
		{"empty file", []byte(""), "T3", 0},
		{"larger than the size limit", bytes.Repeat([]byte("a"), edition.MaxTableBytes+1), "T3", 0},
		{"invalid UTF-8 in a value", render(runA, set(baseRows(), 0, 3, "\xff")), "T3", 0},
		{"no header line", []byte(strings.Join(baseRows()[0], "\t") + "\n"), "T3", 1},
		{"header version v2", []byte("# falco-ctf answers v2 run=" + runA + "\n"), "T3", 1},
		{"header without a run id", []byte("# falco-ctf answers v1\n"), "T3", 1},
		{"run id in upper case", render(strings.ToUpper(runA), nil), "T3", 1},
		{"run id of 31 digits", render(runA[:31], nil), "T3", 1},
		{"run id of 33 digits", render(runA+"0", nil), "T3", 1},
		{"run id with a non-hex digit", render(runA[:31]+"g", nil), "T3", 1},
		{"CRLF line endings", []byte(strings.ReplaceAll(string(full), "\n", "\r\n")), "T3", 1},
		{"double quote in a value", render(runA, set(baseRows(), 0, 3, sentinel+`"x`)), "T3", 2},
		{"three columns", render(runA, [][]string{{"seat-a", demoCID, "who"}}), "T3", 2},
		{"five columns", render(runA, [][]string{{"seat-a", demoCID, "who", sentinel + "-a", sentinel}}), "T3", 2},
		{"empty value column", render(runA, set(baseRows(), 0, 3, "")), "T3", 2},
		{"empty seat column", render(runA, set(baseRows(), 0, 0, "")), "T3", 2},
		{"blank line between rows", render(runA, [][]string{baseRows()[0], {""}, baseRows()[1]}), "T3", 3},
		{"zero-width space in a value", render(runA, set(baseRows(), 1, 3, "aaaa​aaaa")), "T3", 3},
		{"right-to-left override in a value", render(runA, set(baseRows(), 0, 3, sentinel+"‮")), "T3", 2},
		{"NUL in a value", render(runA, set(baseRows(), 0, 3, "x\x00y")), "T3", 2},
		{"no final newline", bytes.TrimSuffix(full, []byte("\n")), "T3", 7},
		{"duplicate row", render(runA, append(baseRows(), baseRows()[0])), "T4", 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tb, err := edition.Parse(c.data)
			if err == nil {
				t.Fatalf("Parse accepted it")
			}
			if tb != nil {
				t.Errorf("Parse returned a table with an error")
			}
			var v *edition.Violation
			if !errors.As(err, &v) {
				t.Fatalf("error is not a *Violation: %v", err)
			}
			if v.Rule != c.rule || v.Line != c.line {
				t.Errorf("got rule %s line %d, want rule %s line %d (%v)", v.Rule, v.Line, c.rule, c.line, err)
			}
			noSecret(t, c.name, err)
		})
	}
}

// A Table prints as a fixed string under every verb and under encoding/json.
func TestTable_PrintsNoValue(t *testing.T) {
	tb := mustParse(t, render(runA, baseRows()))
	texts := []string{
		fmt.Sprintf("%v", tb), fmt.Sprintf("%+v", tb), fmt.Sprintf("%#v", tb), fmt.Sprintf("%s", tb), fmt.Sprintf("%d", tb),
		fmt.Sprintf("%v", *tb), fmt.Sprintf("%+v", *tb), fmt.Sprintf("%#v", *tb),
	}
	b, err := json.Marshal(tb)
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, string(b))
	noSecretIn(t, "Table", texts...)
	for _, s := range texts {
		if !strings.Contains(s, "redacted") {
			t.Errorf("Table printed %q, want the fixed redacted string", s)
		}
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("a good file", func(t *testing.T) {
		tb, err := edition.ReadFile(write("good.tsv", render(runA, baseRows())))
		if err != nil || tb.RunID() != runA {
			t.Fatalf("ReadFile = %v, %v", tb, err)
		}
	})
	t.Run("a missing file", func(t *testing.T) {
		if _, err := edition.ReadFile(filepath.Join(dir, "absent.tsv")); err == nil {
			t.Error("ReadFile accepted a missing file")
		}
	})
	t.Run("a file over the limit", func(t *testing.T) {
		_, err := edition.ReadFile(write("big.tsv", bytes.Repeat([]byte("a"), edition.MaxTableBytes+10)))
		var v *edition.Violation
		if !errors.As(err, &v) || v.Rule != "T3" {
			t.Errorf("ReadFile(big) = %v, want a T3 violation", err)
		}
	})
}
