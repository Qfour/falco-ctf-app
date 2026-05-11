// Package catalog loads challenge metadata from `challenges/<NN>-<slug>/falco-rule.yaml`.
//
// Schema:
//
//	challengeId:   string (defaults to directory name)
//	type:          "trigger" | "evade" (inferred from expectedRules presence if absent)
//	expectedRules: []string  — solve when one of these rules fires
//	forbiddenRules:[]string  — submission rejected if any fired in the last windowSeconds
//	expectedFlag:  string
//	windowSeconds: int (default 10)
package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

type Challenge struct {
	ID             string   `yaml:"challengeId"`
	Type           string   `yaml:"type"`
	ExpectedRules  []string `yaml:"expectedRules"`
	ForbiddenRules []string `yaml:"forbiddenRules"`
	ExpectedFlag   string   `yaml:"expectedFlag"`
	WindowSeconds  int      `yaml:"windowSeconds"`
}

type Catalog map[string]Challenge

// IDs returns challenge IDs in sorted order (stable for /api/state).
func (c Catalog) IDs() []string {
	ids := make([]string, 0, len(c))
	for id := range c {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Load reads every <dir>/<NN>-<slug>/falco-rule.yaml and returns a populated
// catalog. Missing dir returns an empty catalog (matches Python behavior).
func Load(dir string) (Catalog, error) {
	out := make(Catalog)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read catalog dir %q: %w", dir, err)
	}

	// Sort entries to make load order deterministic (matches Python `sorted(...)`).
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "falco-rule.yaml")
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() {
			continue
		}
		ch, err := parseFile(path, e.Name())
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		out[ch.ID] = ch
	}
	return out, nil
}

func parseFile(path, dirName string) (Challenge, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Challenge{}, err
	}
	var ch Challenge
	if err := yaml.Unmarshal(data, &ch); err != nil {
		return Challenge{}, err
	}
	if ch.ID == "" {
		ch.ID = dirName
	}
	if ch.Type == "" {
		if len(ch.ExpectedRules) > 0 {
			ch.Type = "trigger"
		} else {
			ch.Type = "evade"
		}
	}
	if ch.WindowSeconds <= 0 {
		ch.WindowSeconds = 10
	}
	return ch, nil
}
