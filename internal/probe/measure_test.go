package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// Обрыв на локальном конце туннеля - это "Xray ещё не готов", а не приговор ноде
func TestTransientErrorsAreRecognised(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"reset", syscall.ECONNRESET, true},
		{"refused", syscall.ECONNREFUSED, true},
		{"eof", io.EOF, true},
		{"обёрнутый reset", fmt.Errorf("read tcp: %w", syscall.ECONNRESET), true},
		{"текстом", errors.New("read tcp 127.0.0.1:5 ->127.0.0.1:41080: read: connection reset by peer"), true},
		{"настоящий отказ", errors.New("context deadline exceeded"), false},
		{"нет ошибки", nil, false},
	}
	for _, c := range cases {
		if got := isTransient(c.err); got != c.want {
			t.Fatalf("%s: isTransient = %v, want %v", c.name, got, c.want)
		}
	}
}

// Порт, который держит предыдущий Xray, считается занятым, пока его не отпустят
func TestWaitForPortFree(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	if err := waitForPortFree(context.Background(), port, 300*time.Millisecond); err == nil {
		t.Fatal("занятый порт сочли свободным")
	}

	_ = listener.Close()
	if err := waitForPortFree(context.Background(), port, 2*time.Second); err != nil {
		t.Fatalf("освободившийся порт всё ещё занят: %v", err)
	}
}
