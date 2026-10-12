// Command serve is `make e2e-serve` (ADR-0031 D1 (a)): the real scoreboard
// binary seeded to a named state, behind the identity-injecting proxy, so a
// person (or Claude in Chrome) can open the portal in an ordinary browser.
//
// It runs inside the e2e-serve image. The Makefile publishes its one port as
// 127.0.0.1:<port> only; the scoreboard child listens on loopback inside the
// container, and the proxy's upstream is that child alone (harness.NewProxy
// takes no URL). Configuration is SEED, AS and E2E_PORT, each validated; there
// is no other knob, and no secret or real flag is involved (FLAGS_FILE and
// ADMIN_EMAILS are never in the child's env: harness.CheckChildEnv).
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Qfour/falco-ctf-app/internal/e2e/harness"
)

var seedPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-serve:", err)
		os.Exit(1)
	}
}

func run() error {
	seed := os.Getenv("SEED")
	if !seedPattern.MatchString(seed) {
		return fmt.Errorf("SEED=%q is not one of: %s", seed, strings.Join(harness.SeedNames(), ", "))
	}
	user := os.Getenv("AS")
	if user == "" {
		user = "user1"
	}
	email, err := harness.EmailFor(user) // refuses anything but a valid username
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(os.Getenv("E2E_PORT"))
	if err != nil || port < 1024 || port > 65535 {
		return fmt.Errorf("E2E_PORT=%q must be a port between 1024 and 65535", os.Getenv("E2E_PORT"))
	}
	root := os.Getenv("E2E_ROOT")
	if root == "" {
		root = "/app"
	}
	bin := os.Getenv("E2E_SCOREBOARD_BIN")
	challenges := filepath.Join(root, "challenges")
	scenario := filepath.Join(root, "scenarios", "nimbusbreach-full", "scenario.yaml")
	plan, err := harness.LoadPlan(challenges, scenario)
	if err != nil {
		return err
	}

	// The proxy listens on every interface of the container (docker's publish
	// is what restricts it to the host's loopback). The browser's origin is the
	// published one, which is the origin the child's guard must accept.
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	origin := fmt.Sprintf("http://127.0.0.1:%d", port)

	work, err := os.MkdirTemp("", "e2e-serve-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	startCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	child, err := harness.StartScoreboard(startCtx, harness.ScoreboardConfig{
		Binary: bin, WorkDir: work, ChallengesDir: challenges, ScenarioFile: scenario,
		AllowedOrigin: origin, TtydSuffix: harness.TtydSuffix,
	})
	if err != nil {
		_ = ln.Close()
		return err
	}
	defer child.Close()
	if err := harness.NewSeeder(child, email, plan).Seed(startCtx, seed, user); err != nil {
		_ = ln.Close()
		return fmt.Errorf("seed %s: %w", seed, err)
	}
	proxy, err := harness.NewProxy(ln, child, email)
	if err != nil {
		return err
	}
	defer proxy.Close()

	// The one URL to open (the site permission of a browser extension should
	// name this origin only).
	fmt.Printf("e2e-serve: seed %s as %s -> open %s/portal\n", seed, email, origin)
	select {
	case <-ctx.Done():
	case <-child.Done():
		return fmt.Errorf("the scoreboard child exited:\n%s", child.Logs())
	}
	return nil
}
