package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func newEvadeCatalog() Catalog {
	return Catalog{
		"03-stealth-read": {ID: "03-stealth-read", Type: "evade", ExpectedFlag: "FALCO{dev-stealth-read}"},
		"01-initial-recon": {ID: "01-initial-recon", Type: "trigger", ExpectedRules: []string{"r"}},
	}
}

func writeFlags(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "flags.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyFlagOverrides_EmptyPathIsNoop(t *testing.T) {
	c := newEvadeCatalog()
	if err := c.ApplyFlagOverrides(""); err != nil {
		t.Fatalf("empty path should be no-op, got %v", err)
	}
	if c["03-stealth-read"].ExpectedFlag != "FALCO{dev-stealth-read}" {
		t.Fatal("placeholder flag should be untouched")
	}
}

func TestApplyFlagOverrides_OverridesEvadeFlag(t *testing.T) {
	c := newEvadeCatalog()
	p := writeFlags(t, "flags:\n  03-stealth-read: FALCO{real-event-flag}\n")
	if err := c.ApplyFlagOverrides(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c["03-stealth-read"].ExpectedFlag; got != "FALCO{real-event-flag}" {
		t.Fatalf("flag not overridden, got %q", got)
	}
}

func TestApplyFlagOverrides_UnknownChallengeFailsClosed(t *testing.T) {
	c := newEvadeCatalog()
	p := writeFlags(t, "flags:\n  99-nope: FALCO{x}\n")
	if err := c.ApplyFlagOverrides(p); err == nil {
		t.Fatal("expected error for unknown challengeId")
	}
}

func TestApplyFlagOverrides_NonEvadeFailsClosed(t *testing.T) {
	c := newEvadeCatalog()
	p := writeFlags(t, "flags:\n  01-initial-recon: FALCO{x}\n")
	if err := c.ApplyFlagOverrides(p); err == nil {
		t.Fatal("expected error overriding a trigger challenge")
	}
}

func TestApplyFlagOverrides_MalformedFlagFailsClosed(t *testing.T) {
	c := newEvadeCatalog()
	p := writeFlags(t, "flags:\n  03-stealth-read: not-a-flag\n")
	if err := c.ApplyFlagOverrides(p); err == nil {
		t.Fatal("expected error for malformed flag")
	}
}

func TestApplyFlagOverrides_EmptyFileFailsClosed(t *testing.T) {
	c := newEvadeCatalog()
	p := writeFlags(t, "flags: {}\n")
	if err := c.ApplyFlagOverrides(p); err == nil {
		t.Fatal("expected error for empty flags map")
	}
}

func TestApplyFlagOverrides_MissingFileFailsClosed(t *testing.T) {
	c := newEvadeCatalog()
	if err := c.ApplyFlagOverrides("/nonexistent/flags.yaml"); err == nil {
		t.Fatal("expected error for missing file when path is set")
	}
}
