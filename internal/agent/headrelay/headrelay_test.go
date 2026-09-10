package headrelay

import (
	"context"
	"net"
	"testing"
	"time"
)

// Байты ходят в обе стороны и не портятся: нода тут труба, а не участник
func TestRelayCarriesBytesBothWays(t *testing.T) {
	head, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = head.Close() }()
	go func() {
		conn, err := head.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(append([]byte("ответ:"), buf[:n]...))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay := New("127.0.0.1:0", head.Addr().String(), nil)
	// Слушатель поднимаем сами, чтобы узнать выданный порт
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay.listen = ln.Addr().String()
	_ = ln.Close()
	go relay.Run(ctx)

	var client net.Conn
	for i := 0; i < 50; i++ {
		client, err = net.Dial("tcp", relay.listen)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("до трубы не дозвонились: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("запрос")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("ответ не доехал: %v", err)
	}
	if got := string(buf[:n]); got != "ответ:запрос" {
		t.Fatalf("байты испортились: %q", got)
	}
}

// Труба не резиновая: зондов единицы, и сотня соединений означала бы, что нас
// пользуют не по назначению
func TestRelayRefusesAFlood(t *testing.T) {
	relay := New("", "127.0.0.1:1", nil)
	for i := 0; i < maxConns; i++ {
		if !relay.take() {
			t.Fatalf("отказали на %d соединении из %d", i, maxConns)
		}
	}
	if relay.take() {
		t.Fatal("пустили сверх потолка")
	}
	relay.give()
	if !relay.take() {
		t.Fatal("освободившееся место не переиспользовали")
	}
}
