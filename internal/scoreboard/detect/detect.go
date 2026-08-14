// Package detect implements the scoring.DetectRunner port: it wraps a
// participant-submitted Falco `condition:` into a fixed rule skeleton, runs the
// `falco -V` compile gate, and — only if it compiles — replays the evasion and
// benign captures, returning the fire counts.
//
// Two implementations share the skeleton/macro-file assembly and the fire
// -counting logic in this file:
//
//   - LocalExec (localexec.go): runs the upstream Falco binary/container against
//     captures on the local filesystem. For dev / colima / CI / unit-adjacent
//     E2E — prod-independent.
//   - K8sJob (k8sjob.go): creates a per-submission Kubernetes Job in a dedicated
//     grader namespace (prod). Its result is accepted ONLY on an exact
//     namespace + Job-name + label + status.succeeded match (never an untrusted
//     count from the pod).
//
// Neither implementation lives in the scoring package: scoring depends only on
// the scoring.DetectRunner interface, so the solve rules stay falco-free and
// unit-testable with a fake runner (scoring/scoring_test.go), while this
// package's own falco-adjacent logic is covered by localexec_test.go (Grade via
// a fake falcoRunner: compile-fail → invalid, replay fire combinations →
// status, and the post-compile replay fail-closed) and k8sjob_test.go
// (acceptResult / jobName / sanitizeLabel).
//
// Safety model (see docs/detect-challenge-design.md §3-4 and the security-lead
// threat model): the condition is UNTRUSTED. It is delivered to Falco via a
// FILE (never argv/env interpolation), size-capped before a runner is invoked,
// and `falco -V` is the compile gate that runs BEFORE any replay — Falco's
// condition grammar is a closed expression language with no OS/shell access, so
// a malformed / "injection" condition is merely a compile error (invalid=true),
// never executed. Replay is driverless (engine.kind: replay) so the grader needs
// no privilege / kernel driver.
package detect

import (
	"fmt"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// MaxConditionBytes bounds the participant condition size BEFORE it is handed to
// any runner (input hardening, design §3.3). 4 KiB is far larger than any real
// Falco condition while cheaply capping a pathological submission.
const MaxConditionBytes = 4 << 10

// curatedMacros defines the minimal macro/list vocabulary a detect condition may
// reference. We deliberately do NOT load the full stock Falco ruleset into the
// grader: that would let a condition reference arbitrary unrelated macros and
// enlarge the compile surface. Only the names a mission's detect.allowedMacros
// lists are emitted (see buildRulesFile); `falco -V` fails closed
// (LOAD_ERR_COMPILE_CONDITION) on any reference to a name not emitted here, which
// the Grader maps to DetectInvalidCondition.
//
// These are intentionally small, self-contained definitions (no dependency on
// the stock macro graph) so the curated file compiles on its own. Keep them
// aligned with the teaching intent of each mission; a new allowedMacros name
// must be added here or the condition using it will not compile.
var curatedMacros = map[string]string{
	// open_read: an open/openat(2) for reading (the read half of file access).
	"open_read": `evt.type in (open,openat,openat2) and evt.is_open_read=true`,
	// spawned_process: a process actually executing (execve return), not the fork.
	"spawned_process": `evt.type in (execve,execveat) and evt.dir=<`,
	// sensitive_files: the classic credential/secret file set (shadow, ssh keys,
	// aws/gcloud creds). Path-string based on purpose — the mission-3 lesson is
	// that /proc/self/root/... reaches the same inode without matching these
	// literal paths, so a naive path match misses the evasion.
	"sensitive_files": `fd.name startswith /etc/shadow or fd.name startswith /etc/pam.d or ` +
		`fd.name startswith /etc/sudoers or fd.name in (/etc/passwd, /etc/gshadow) or ` +
		`fd.name startswith /root/.ssh or fd.name contains /.aws/credentials`,
	// private_key_or_password: files whose name suggests a key or password store.
	"private_key_or_password": `fd.name endswith .pem or fd.name endswith .key or ` +
		`fd.name contains id_rsa or fd.name contains id_dsa or fd.name endswith /shadow`,
}

// buildRulesFile assembles the curated macros the mission allows plus the fixed
// rule that wraps the participant condition. It is shared by both runners so the
// compile surface and rule skeleton are identical everywhere. The participant
// controls ONLY the condition body; name/output/priority and the macro set are
// fixed by the mission (design §1.1/§4).
//
// It returns an error if a mission lists an allowedMacros name we do not define
// (curatedMacros) — a catalog/authoring mistake that must fail fast rather than
// produce a rules file that silently omits the macro (which would then surface
// as a confusing "invalid condition" to the participant).
func buildRulesFile(d *catalog.Detect, condition string) (string, error) {
	if d == nil {
		return "", fmt.Errorf("detect: nil Detect block")
	}
	var b strings.Builder
	// Emit only the macros this mission allows, in listed order.
	for _, name := range d.AllowedMacros {
		def, ok := curatedMacros[name]
		if !ok {
			return "", fmt.Errorf("detect: allowedMacros references undefined macro %q (add it to curatedMacros)", name)
		}
		fmt.Fprintf(&b, "- macro: %s\n  condition: (%s)\n", name, def)
	}
	ruleName := d.RuleName
	if ruleName == "" {
		ruleName = catalog.DefaultDetectRuleName
	}
	// The participant condition is embedded as a YAML block scalar so newlines /
	// quotes in it cannot break the rules document structure. It is still just a
	// Falco condition (a closed expression language) — `falco -V` is the gate.
	b.WriteString("- rule: ")
	b.WriteString(ruleName)
	b.WriteString("\n")
	b.WriteString("  desc: participant-authored detection (graded by capture replay)\n")
	b.WriteString("  condition: >\n")
	for _, line := range strings.Split(condition, "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("  output: participant_detect rule=%rule file=%fd.name proc=%proc.name\n")
	b.WriteString("  priority: WARNING\n")
	return b.String(), nil
}

// countFires counts the number of fired-rule JSON lines in a Falco replay's
// stdout that match the participant rule name. Falco's JSON output emits one
// object per alert with a "rule":"<name>" field; we count exact matches of the
// wrapped rule name. Robust to surrounding log lines (only lines carrying the
// exact rule token are counted).
func countFires(stdout, ruleName string) int {
	needle := `"rule":"` + ruleName + `"`
	needleSp := `"rule": "` + ruleName + `"` // tolerate a space after the colon
	n := 0
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, needle) || strings.Contains(line, needleSp) {
			n++
		}
	}
	return n
}
