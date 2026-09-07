// Package xrayproc supervises the Xray child process.
//
// The shape follows 3x-ui internal/xray/process.go, which has been running this
// fleet for a while: atomic config write, SIGTERM then SIGKILL, and a crash tail
// so a failure says why instead of just "exited"
package xrayproc

import (
	"bufio"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// gracefulStop bounds how long SIGTERM gets before SIGKILL. Xray closes fast, so
// a longer wait only delays recovery when it is already wedged
const gracefulStop = 5 * time.Second

// crashTailLines is how much of the tail is kept for the error message. Enough
// to carry the parse error Xray prints before dying, not enough to ship a log
const crashTailLines = 20

// ErrNotRunning means an operation needs a live process
var ErrNotRunning = errors.New("xrayproc: not running")

// Process is a supervised Xray
type Process struct {
	binary     string
	configPath string

	mu      sync.Mutex
	cmd     *exec.Cmd
	tail    []string
	exited  chan struct{}
	lastErr error
}

// New builds a supervisor. Nothing starts until Start is called
func New(binary, configPath string) *Process {
	return &Process{binary: binary, configPath: configPath}
}

// Running reports whether the child is alive
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.exited != nil && !closed(p.exited)
}

func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// Start launches Xray against the config already on disk
func (p *Process) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.exited != nil && !closed(p.exited) {
		return nil
	}
	cmd := exec.Command(p.binary, "-c", p.configPath)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	p.cmd = cmd
	p.tail = nil
	p.lastErr = nil
	exited := make(chan struct{})
	p.exited = exited

	go p.readTail(stderr)
	go func() {
		waitErr := cmd.Wait()
		p.mu.Lock()
		p.lastErr = waitErr
		p.mu.Unlock()
		close(exited)
	}()
	return nil
}

// readTail keeps the last lines so a crash can say why. Without it a failed
// start is just a non-zero exit and the operator has nothing to go on
func (p *Process) readTail(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		p.mu.Lock()
		p.tail = append(p.tail, line)
		if len(p.tail) > crashTailLines {
			p.tail = p.tail[len(p.tail)-crashTailLines:]
		}
		p.mu.Unlock()
	}
}

// Tail returns the retained stderr lines
func (p *Process) Tail() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.tail...)
}

// Stop asks the process to leave, then insists
func (p *Process) Stop() error {
	p.mu.Lock()
	cmd, exited := p.cmd, p.exited
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil || exited == nil {
		return ErrNotRunning
	}
	if closed(exited) {
		return nil
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-exited:
		return nil
	case <-time.After(gracefulStop):
	}
	return cmd.Process.Kill()
}

// Wait blocks until the process leaves, returning why
func (p *Process) Wait() error {
	p.mu.Lock()
	exited := p.exited
	p.mu.Unlock()
	if exited == nil {
		return ErrNotRunning
	}
	<-exited
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}
