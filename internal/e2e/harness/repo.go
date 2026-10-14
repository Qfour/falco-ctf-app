package harness

import (
	"errors"
	"os"
	"path/filepath"
)

// RepoRoot walks up from dir to the directory holding go.mod.
func RepoRoot(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("harness: go.mod not found above the working directory")
		}
		dir = parent
	}
}
