package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ChildEnvAllowlist is every environment variable the scoreboard child gets.
// The env is built from this list alone and never inherits the parent's
// (ADR-0031 D1 (b)): a flag file, an admin allowlist or a webhook secret in the
// developer's shell must not reach a binary the harness is about to serve.
var ChildEnvAllowlist = []string{
	"LISTEN_ADDR",
	"SCOREBOARD_DB",
	"ALLOWED_ORIGINS",
	"CHALLENGES_DIR",
	"SCENARIO_FILE",
	"PORTAL_TTYD_SUFFIX",
	// QUEST_ENABLED is read by the P28 Quest code (ADR-0029 D3: unset = off).
	// It is passed so that a run is never silently the Quest-off run once that
	// code lands. cmd/scoreboard on main does not read it yet.
	"QUEST_ENABLED",
	// EXPECTED_EMAIL_DOMAIN is read by the ADR-0034 S2 identity code: self is
	// then the exact "<user>@<domain>" and an unset domain matches nobody
	// (fail-closed), which would turn every seed's self-scope read into a 403.
	// It is IdentityDomain, the domain of every synthetic e-mail (EmailFor), so
	// the two cannot drift. cmd/scoreboard on main does not read it yet.
	"EXPECTED_EMAIL_DOMAIN",
}

// childEnvForbidden are the variables whose presence in the child's env is a
// harness bug, named so that the failure says why: they hand the child real
// privileges (admin identity, real flags, webhook trust).
var childEnvForbidden = []string{
	"ADMIN_EMAILS",
	"FLAGS_FILE",
	"FALCO_WEBHOOK_SHARED_SECRET",
	"WEBHOOK_SECRET_MODE",
	"HIDDEN_USERS",
	"DETECT_RUNNER",
}

// ScoreboardConfig describes one child.
type ScoreboardConfig struct {
	// Binary is the cmd/scoreboard executable (built like scoreboard/Dockerfile).
	Binary string
	// WorkDir is a fresh directory: the SQLite files live there.
	WorkDir string
	// ChallengesDir and ScenarioFile are the repository's real catalog.
	ChallengesDir string
	ScenarioFile  string
	// AllowedOrigin is the proxy's origin: the one origin the origin guard
	// accepts for browser writes.
	AllowedOrigin string
	// TtydSuffix is a synthetic ".test" suffix.
	TtydSuffix string
	// ListenAddr is "127.0.0.1:<port>"; empty picks a free loopback port.
	ListenAddr string
}

// Env builds the child's whole environment from the allowlist and checks it.
func (c ScoreboardConfig) Env() ([]string, error) {
	// The SQLite files go in WorkDir: an empty or relative one would put them
	// in whatever directory the parent runs in (a package dir of the repo).
	if c.WorkDir == "" || !filepath.IsAbs(c.WorkDir) {
		return nil, fmt.Errorf("harness: ScoreboardConfig.WorkDir %q must be an absolute directory", c.WorkDir)
	}
	listen := c.ListenAddr
	if listen == "" {
		var err error
		if listen, err = freeLoopbackAddr(); err != nil {
			return nil, err
		}
	}
	env := []string{
		"LISTEN_ADDR=" + listen,
		"SCOREBOARD_DB=" + filepath.Join(c.WorkDir, "scoreboard.db"),
		"ALLOWED_ORIGINS=" + c.AllowedOrigin,
		"CHALLENGES_DIR=" + c.ChallengesDir,
		"SCENARIO_FILE=" + c.ScenarioFile,
		"PORTAL_TTYD_SUFFIX=" + c.TtydSuffix,
		"QUEST_ENABLED=true",
		"EXPECTED_EMAIL_DOMAIN=" + IdentityDomain,
	}
	if err := CheckChildEnv(env); err != nil {
		return nil, err
	}
	return env, nil
}

// CheckChildEnv is the assertion Start runs on the env it is about to give the
// child (ADR-0031 D1 (b), V8): only allowlisted names, none of the privileged
// ones, a loopback listen address, an absolute DB path, exactly one http(s)
// origin, a reserved-TLD ttyd suffix and identity domain.
func CheckChildEnv(env []string) error {
	seen := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return fmt.Errorf("harness: malformed child env entry %q", kv)
		}
		if _, dup := seen[k]; dup {
			return fmt.Errorf("harness: child env sets %s twice", k)
		}
		seen[k] = v
	}
	for _, k := range childEnvForbidden {
		if _, ok := seen[k]; ok {
			return fmt.Errorf("harness: child env must not contain %s", k)
		}
	}
	allowed := map[string]bool{}
	for _, k := range ChildEnvAllowlist {
		allowed[k] = true
	}
	var extra []string
	for k := range seen {
		if !allowed[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("harness: child env has names outside the allowlist: %s", strings.Join(extra, ", "))
	}
	for _, k := range ChildEnvAllowlist {
		if seen[k] == "" {
			return fmt.Errorf("harness: child env needs a non-empty %s", k)
		}
	}
	host, _, err := net.SplitHostPort(seen["LISTEN_ADDR"])
	if err != nil {
		return fmt.Errorf("harness: LISTEN_ADDR %q: %w", seen["LISTEN_ADDR"], err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("harness: LISTEN_ADDR %q must be a loopback IP literal", seen["LISTEN_ADDR"])
	}
	if db := seen["SCOREBOARD_DB"]; !filepath.IsAbs(db) {
		return fmt.Errorf("harness: SCOREBOARD_DB %q must be an absolute path (a relative one lands in the parent's working directory)", db)
	}
	if o := seen["ALLOWED_ORIGINS"]; strings.Contains(o, ",") || !isOrigin(o) {
		return fmt.Errorf("harness: ALLOWED_ORIGINS %q must be exactly one scheme://host[:port] origin", o)
	}
	if s := seen["PORTAL_TTYD_SUFFIX"]; !strings.HasSuffix(s, ".test") {
		return fmt.Errorf("harness: PORTAL_TTYD_SUFFIX %q must end in the reserved .test TLD", s)
	}
	if d := seen["EXPECTED_EMAIL_DOMAIN"]; d != IdentityDomain {
		return fmt.Errorf("harness: EXPECTED_EMAIL_DOMAIN %q must be the synthetic identity domain %q (the domain EmailFor builds every e-mail with)", d, IdentityDomain)
	}
	if seen["QUEST_ENABLED"] != "true" {
		return fmt.Errorf("harness: QUEST_ENABLED must be true, got %q", seen["QUEST_ENABLED"])
	}
	return nil
}

func isOrigin(s string) bool {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func freeLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	return addr, ln.Close()
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// Scoreboard is a running cmd/scoreboard child.
type Scoreboard struct {
	addr string
	cmd  *exec.Cmd
	logs *logBuffer
	stop context.CancelFunc
	done chan struct{}
	err  error // set before done is closed
}

func (s *Scoreboard) upstreamAddr() string { return s.addr }

// URL is the child's own base URL (loopback). Seeds use it directly; browsers
// reach the child only through the Proxy.
func (s *Scoreboard) URL() string { return "http://" + s.addr }

// Logs returns what the child has written to stdout and stderr so far.
func (s *Scoreboard) Logs() string { return s.logs.String() }

// Done is closed when the child has exited.
func (s *Scoreboard) Done() <-chan struct{} { return s.done }

// Close asks the child to stop (SIGTERM, then SIGKILL once WaitDelay has
// passed) and waits for it.
func (s *Scoreboard) Close() {
	s.stop()
	<-s.done
}

// StartScoreboard runs the binary with the allowlisted env and returns once it
// accepts connections and answers /healthz. ctx bounds the start-up only: a
// failure to come up in time is the deadline, never a sleep.
func StartScoreboard(ctx context.Context, c ScoreboardConfig) (*Scoreboard, error) {
	if c.Binary == "" {
		return nil, errors.New("harness: ScoreboardConfig.Binary is empty (set E2E_SCOREBOARD_BIN)")
	}
	if _, err := os.Stat(c.Binary); err != nil {
		return nil, fmt.Errorf("harness: scoreboard binary: %w", err)
	}
	env, err := c.Env()
	if err != nil {
		return nil, err
	}
	// Assert the exact slice that is handed to exec, not a copy of it.
	if err := CheckChildEnv(env); err != nil {
		return nil, err
	}
	addr := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "LISTEN_ADDR="); ok {
			addr = v
		}
	}

	logs := newLogBuffer()
	// The child's lifetime is its own context, not ctx (which only bounds the
	// start-up): cancelling it sends SIGTERM and, after WaitDelay, SIGKILL.
	killCtx, stop := context.WithCancel(context.Background())
	cmd := exec.CommandContext(killCtx, c.Binary)
	cmd.Env = env
	cmd.Dir = c.WorkDir
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		stop()
		return nil, fmt.Errorf("harness: start scoreboard: %w", err)
	}
	s := &Scoreboard{addr: addr, cmd: cmd, logs: logs, stop: stop, done: make(chan struct{})}
	go func() {
		s.err = cmd.Wait()
		close(s.done)
	}()

	fail := func(why string, cause error) (*Scoreboard, error) {
		s.Close()
		return nil, fmt.Errorf("harness: scoreboard %s: %w\nchild log:\n%s", why, cause, logs.String())
	}
	// The child logs "listening" just before ListenAndServe, so wait for that
	// line (an event, not a clock), then dial until the socket is bound — the
	// gap is microseconds.
	select {
	case <-logs.listening:
	case <-s.done:
		return fail("exited during start-up", errOrExit(s.err))
	case <-ctx.Done():
		return fail("did not report listening", ctx.Err())
	}
	for {
		conn, derr := net.Dial("tcp", addr)
		if derr == nil {
			_ = conn.Close()
			break
		}
		select {
		case <-s.done:
			return fail("exited during start-up", errOrExit(s.err))
		case <-ctx.Done():
			return fail("did not accept connections", ctx.Err())
		default:
			runtime.Gosched()
		}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL()+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fail("/healthz", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail("/healthz", fmt.Errorf("status %d", resp.StatusCode))
	}
	return s, nil
}

func errOrExit(err error) error {
	if err == nil {
		return errors.New("exit status 0")
	}
	return err
}

// logBuffer collects a child's output and signals the first "listening" line.
type logBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	listening chan struct{}
	signalled bool
}

func newLogBuffer() *logBuffer { return &logBuffer{listening: make(chan struct{})} }

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buf.Write(p)
	if !l.signalled && bytes.Contains(l.buf.Bytes(), []byte(`"msg":"listening"`)) {
		l.signalled = true
		close(l.listening)
	}
	return n, err
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
