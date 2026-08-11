package detect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Qfour/falco-ctf-app/internal/catalog"
)

// LocalExec is the dev/colima/CI DetectRunner. It runs the upstream Falco
// (a binary on PATH, or a container) against captures on the local filesystem:
// the compile gate (`falco -V`) then two driverless `engine.kind: replay`
// passes. It is prod-INDEPENDENT — the prod path is K8sJob.
//
// Falco invocation is abstracted behind runFalco so tests and the docker/binary
// variants share the same assemble-and-count body. The concrete docker variant
// mounts the temp rules dir and the challenge capture dir read-only into the
// falco image.
type LocalExec struct {
	cat catalog.Catalog
	// challengesDir is the catalog root on disk (e.g. /app/challenges). Captures
	// are located at <challengesDir>/<challenge.Dir()>/<resolved relative path>.
	// The resolved relative path is the single-source, load-validated value from
	// catalog.Detect (no `..`, in-bounds); we join it under this trusted base only.
	challengesDir string
	// runFalco runs one falco invocation. args are falco CLI args; rulesDir and
	// capturesDir are host paths the invocation must be able to read (the docker
	// variant mounts them). It returns combined stdout and a non-nil error only
	// on an infrastructure failure (could not start / timeout). A non-zero falco
	// exit for `-V` is signalled via exitCode, NOT err, so the caller can map a
	// compile failure to invalid=true rather than an infra error.
	runFalco falcoRunner
}

type falcoRunner func(ctx context.Context, rulesDir, capturesDir string, args ...string) (stdout string, exitCode int, err error)

// NewLocalExec builds a LocalExec that grades by shelling out to the falcoImage
// container via `docker run` (colima-friendly, no host falco binary needed).
// challengesDir is the on-disk catalog root.
func NewLocalExec(cat catalog.Catalog, challengesDir, falcoImage string) *LocalExec {
	return &LocalExec{
		cat:           cat,
		challengesDir: challengesDir,
		runFalco:      dockerFalcoRunner(falcoImage),
	}
}

// Grade implements scoring.DetectRunner. See the interface contract: invalid=true
// on a compile failure (no replay run), else the two replay fire counts.
func (l *LocalExec) Grade(ctx context.Context, cid, condition string) (evasionFires, benignFires int, invalid bool, err error) {
	if len(condition) > MaxConditionBytes {
		// Defense-in-depth: the handler also caps this, but never trust a single
		// gate. Oversized input is treated as invalid (never run).
		return 0, 0, true, nil
	}
	ch, ok := l.cat[cid]
	if !ok {
		return 0, 0, false, fmt.Errorf("detect: unknown challenge %q", cid)
	}
	if ch.Type != "detect" || ch.Detect == nil {
		return 0, 0, false, fmt.Errorf("detect: challenge %q is not a detect challenge", cid)
	}

	// Assemble the rules file (curated macros + wrapped participant condition).
	rulesText, err := buildRulesFile(ch.Detect, condition)
	if err != nil {
		return 0, 0, false, err
	}

	// Temp rules dir (host); mounted read-only into the falco container.
	rulesDir, err := os.MkdirTemp("", "detect-rules-")
	if err != nil {
		return 0, 0, false, fmt.Errorf("detect: temp dir: %w", err)
	}
	defer os.RemoveAll(rulesDir)
	rulesPath := filepath.Join(rulesDir, "participant.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesText), 0o600); err != nil {
		return 0, 0, false, fmt.Errorf("detect: write rules: %w", err)
	}

	// Captures dir = <challengesDir>/<dir>. Join the single-source relative paths
	// under this trusted base only (they carry no `..`; validated at load).
	capturesDir := filepath.Join(l.challengesDir, ch.Dir())
	evasionRel := ch.Detect.EvasionCapturePath
	benignRel := ch.Detect.BenignCapturePath

	// 1) Compile gate: `falco -V` on the assembled rules. A non-zero exit means
	// the condition did not compile (bad syntax / undefined macro) → invalid.
	_, code, err := l.runFalco(ctx, rulesDir, capturesDir, "-V", "/rules/participant.yaml")
	if err != nil {
		return 0, 0, false, fmt.Errorf("detect: compile gate: %w", err)
	}
	if code != 0 {
		return 0, 0, true, nil // invalid condition — do NOT replay
	}

	// 2) Two driverless replay passes. Count fires of the wrapped rule name.
	ef, err := l.replay(ctx, rulesDir, capturesDir, evasionRel, ch.Detect.RuleName)
	if err != nil {
		return 0, 0, false, err
	}
	bf, err := l.replay(ctx, rulesDir, capturesDir, benignRel, ch.Detect.RuleName)
	if err != nil {
		return 0, 0, false, err
	}
	return ef, bf, false, nil
}

// replay runs one `engine.kind: replay` pass over captureRel (relative to the
// mounted captures dir) and counts fires of ruleName in the JSON output.
func (l *LocalExec) replay(ctx context.Context, rulesDir, capturesDir, captureRel, ruleName string) (int, error) {
	// The capture is referenced by its in-container path under /captures. We build
	// the engine.replay config inline via falco -c overrides is not supported for
	// nested keys on the CLI in 0.43, so we pass a small config file written into
	// the rules dir (also mounted). Keep replay-only: engine.kind=replay,
	// grpc/http_output/plugins disabled, stdout json only.
	cfgName := "replay-" + sanitize(captureRel) + ".yaml"
	cfg := replayConfig("/captures/" + filepath.ToSlash(captureRel))
	if err := os.WriteFile(filepath.Join(rulesDir, cfgName), []byte(cfg), 0o600); err != nil {
		return 0, fmt.Errorf("detect: write replay cfg: %w", err)
	}
	stdout, code, err := l.runFalco(ctx, rulesDir, capturesDir,
		"-c", "/rules/"+cfgName,
		"-r", "/rules/participant.yaml",
	)
	if err != nil {
		return 0, fmt.Errorf("detect: replay %s: %w", captureRel, err)
	}
	// Fail-closed: the compile gate (`falco -V`) has already passed, so a non-zero
	// exit HERE is not an invalid condition — it is a replay infrastructure failure
	// (corrupt/unreadable capture, OOM, driverless-replay error). We must NOT treat
	// its (possibly 0) fire count as a verdict: a benign replay that crashes with 0
	// fires would otherwise look like "no false positive" and could mis-solve an
	// evasion-firing condition. Surface it as an infra error so the Grader returns
	// a 500 and never credits a solve (design §3.3 fail-closed; regression-pinned
	// in localexec_test.go).
	if code != 0 {
		return 0, fmt.Errorf("detect: replay %s: falco exited %d (post-compile replay failure)", captureRel, code)
	}
	return countFires(stdout, ruleName), nil
}

// replayConfig is the replay-only Falco config: engine.kind=replay against the
// given capture, JSON stdout, all outputs/plugins disabled (design §3, k8s-Job
// §3.2). No network, no gRPC, no HTTP output — replay is local file I/O only.
func replayConfig(captureFile string) string {
	return "engine:\n" +
		"  kind: replay\n" +
		"  replay:\n" +
		"    capture_file: " + captureFile + "\n" +
		"stdout_output:\n" +
		"  enabled: true\n" +
		"json_output: true\n" +
		"json_include_output_property: true\n" +
		"http_output:\n" +
		"  enabled: false\n" +
		"grpc:\n" +
		"  enabled: false\n" +
		"grpc_output:\n" +
		"  enabled: false\n" +
		"load_plugins: []\n"
}

// sanitize maps a capture relative path to a filesystem-safe config file token.
func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", ".", "_", " ", "_")
	return r.Replace(s)
}

// defaultGraderUID is the non-root UID the local grader container runs as.
// 65532 = distroless nonroot, matching the scoreboard/auth-policy runtime user
// (conventions I2) so the defense-in-depth posture is consistent across the app.
// Driverless replay reads only the read-only /rules and /captures mounts and
// writes nothing, so it needs no specific uid — any non-root uid suffices. If a
// future grader image cannot run `falco -V`/replay as this uid, override it
// rather than dropping back to root (see design note; keep it non-root).
const defaultGraderUID = "65532:65532"

// dockerFalcoRunner returns a falcoRunner that invokes the falcoImage via
// `docker run`, mounting the rules dir at /rules and the captures dir at
// /captures (both read-only). Hardened defense-in-depth: no network
// (--network none), read-only rootfs, all caps dropped, no-new-privileges, and
// non-root --user (defaultGraderUID) — replay is driverless so it needs neither
// root nor a kernel driver. The container exit code is returned as exitCode so a
// `-V` compile failure is distinguishable from an infra failure.
func dockerFalcoRunner(falcoImage string) falcoRunner {
	return func(ctx context.Context, rulesDir, capturesDir string, args ...string) (string, int, error) {
		dockerArgs := []string{
			"run", "--rm",
			"--network", "none",
			"--read-only",
			"--cap-drop", "ALL",
			"--security-opt", "no-new-privileges",
			"--user", defaultGraderUID,
			"-v", rulesDir + ":/rules:ro",
			"-v", capturesDir + ":/captures:ro",
			falcoImage, "falco",
		}
		dockerArgs = append(dockerArgs, args...)
		cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				// falco/-V non-zero exit is an expected "invalid" signal, not infra.
				return string(out), ee.ExitCode(), nil
			}
			// docker itself failed to run (not found, daemon down, timeout).
			return string(out), -1, err
		}
		return string(out), 0, nil
	}
}
