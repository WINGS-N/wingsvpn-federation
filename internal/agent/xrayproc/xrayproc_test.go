package xrayproc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBinary writes a shell script standing in for xray, so the supervisor is
// tested without a 40 MB download
func fakeBinary(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-xray")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitUntil(t *testing.T, cond func() bool, why string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", why)
}

func TestStartAndStop(t *testing.T) {
	p := New(fakeBinary(t, "sleep 30\n"), "/dev/null")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, p.Running, "the process to come up")
	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitUntil(t, func() bool { return !p.Running() }, "the process to leave")
}

// A process that ignores SIGTERM must still die, or a wedged Xray blocks every
// config change until somebody logs in
func TestStopKillsAProcessThatIgnoresSigterm(t *testing.T) {
	// The script announces itself only after installing the trap: Running means
	// started, not ready, and signalling in that gap kills it with the default
	// disposition instead of testing anything
	p := New(fakeBinary(t, "trap '' TERM\necho armed >&2\nsleep 30\n"), "/dev/null")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool {
		return strings.Contains(strings.Join(p.Tail(), "\n"), "armed")
	}, "the trap to be installed")

	start := time.Now()
	if err := p.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitUntil(t, func() bool { return !p.Running() }, "the stubborn process to be killed")
	if elapsed := time.Since(start); elapsed < gracefulStop {
		t.Errorf("stop took %s, so SIGTERM was never given its chance", elapsed)
	}
}

// A failed start has to say why. Without the tail an operator sees only a
// non-zero exit and has nothing to work with
func TestCrashTailCarriesTheReason(t *testing.T) {
	p := New(fakeBinary(t, "echo 'infra/conf: failed to parse json' >&2\nexit 23\n"), "/dev/null")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	if err := p.Wait(); err == nil {
		t.Error("a process exiting 23 was reported as clean")
	}
	tail := strings.Join(p.Tail(), "\n")
	if !strings.Contains(tail, "failed to parse json") {
		t.Errorf("tail did not keep the reason: %q", tail)
	}
}

// The tail must stay bounded, or a chatty Xray slowly eats memory
func TestTailIsBounded(t *testing.T) {
	p := New(fakeBinary(t, "i=0; while [ $i -lt 200 ]; do echo line$i >&2; i=$((i+1)); done\n"), "/dev/null")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	_ = p.Wait()
	waitUntil(t, func() bool { return len(p.Tail()) > 0 }, "tail lines")
	if got := len(p.Tail()); got > crashTailLines {
		t.Errorf("tail kept %d lines, want at most %d", got, crashTailLines)
	}
}

func TestStopWithoutStart(t *testing.T) {
	p := New("/nonexistent", "/dev/null")
	if err := p.Stop(); err != ErrNotRunning {
		t.Errorf("err = %v, want ErrNotRunning", err)
	}
}

// Starting twice must not orphan the first child, leaving two Xrays fighting
// over the same port
func TestDoubleStartIsIgnored(t *testing.T) {
	p := New(fakeBinary(t, "sleep 30\n"), "/dev/null")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, p.Running, "the process to come up")
	first := p.cmd.Process.Pid
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	if p.cmd.Process.Pid != first {
		t.Error("a second Start spawned another process instead of keeping the first")
	}
	_ = p.Stop()
}
