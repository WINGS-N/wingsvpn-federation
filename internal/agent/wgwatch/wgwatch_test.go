package wgwatch

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// clientHello собирает настоящий ClientHello с указанным именем
func clientHello(sni string) []byte {
	var ext []byte
	// server_name: тип 0, длина, список имён
	name := []byte(sni)
	list := append([]byte{0x00}, byte(len(name)>>8), byte(len(name)))
	list = append(list, name...)
	body := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	ext = append(ext, 0x00, 0x00, byte(len(body)>>8), byte(len(body)))
	ext = append(ext, body...)

	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0x00)                // session id
	hello = append(hello, 0x00, 0x02, 0x13, 0x01)
	hello = append(hello, 0x01, 0x00)
	hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
	hello = append(hello, ext...)

	handshake := append([]byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	record := append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return record
}

// ipv4TCP заворачивает нагрузку в IP и TCP так, как оно приходит с wg
func ipv4TCP(src [4]byte, dstPort uint16, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 4<<4 | 5
	ip[9] = 6
	copy(ip[12:16], src[:])
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	return append(ip, tcp...)
}

// Имя и отпечаток достаются из живого пакета, а адрес пира сохраняется: по нему
// башка и узнаёт человека
func TestSeesTheNameAndThePeer(t *testing.T) {
	var got []Sighting
	w := New("wg0", func(s Sighting) { got = append(got, s) })
	w.handle(ipv4TCP([4]byte{10, 8, 0, 5}, 443, clientHello("rutracker.org")))

	if len(got) != 1 {
		t.Fatalf("наблюдение не выписано: %+v", got)
	}
	if got[0].Domain != "rutracker.org" {
		t.Fatalf("имя разобрано криво: %q", got[0].Domain)
	}
	if got[0].Address != "10.8.0.5" {
		t.Fatalf("адрес пира потерян: %q", got[0].Address)
	}
	if got[0].JA4 == "" {
		t.Fatal("отпечаток не посчитан")
	}
}

// Одно и то же имя в окне интересно один раз: браузер открывает к хосту десятки
// соединений, и слать их все наверх незачем
func TestRepeatsAreSquashed(t *testing.T) {
	var got []Sighting
	w := New("wg0", func(s Sighting) { got = append(got, s) })
	packet := ipv4TCP([4]byte{10, 8, 0, 5}, 443, clientHello("example.org"))
	w.handle(packet)
	w.handle(packet)
	if len(got) != 1 {
		t.Fatalf("повтор не схлопнулся: %d", len(got))
	}
	// А через окно - снова интересно
	w.now = func() time.Time { return time.Now().Add(2 * dedupWindow) }
	w.handle(packet)
	if len(got) != 2 {
		t.Fatalf("после окна наблюдение не выписали: %d", len(got))
	}
}

// Чужие порты и не-TLS мимо: на 443 ходит веб, остальное нас не касается
func TestOnlyHttpsIsRead(t *testing.T) {
	var got []Sighting
	w := New("wg0", func(s Sighting) { got = append(got, s) })
	w.handle(ipv4TCP([4]byte{10, 8, 0, 5}, 25, clientHello("mail.example")))
	w.handle(ipv4TCP([4]byte{10, 8, 0, 5}, 443, []byte("GET / HTTP/1.1\r\n")))
	if len(got) != 0 {
		t.Fatalf("прочитали лишнее: %+v", got)
	}
}

// Битый пакет не должен ронять наблюдателя
func TestGarbageIsSurvived(t *testing.T) {
	w := New("wg0", func(Sighting) { t.Fatal("из мусора выписали наблюдение") })
	w.handle([]byte{0x45})
	w.handle(make([]byte, 19))
	w.handle([]byte{0x60, 0x00, 0x00})
}

// fakeSource отдаёт заготовленные пакеты, а между ними молчит: так же ведёт
// себя сокет на тихом интерфейсе
type fakeSource struct {
	packets [][]byte
	quiet   int
	closed  bool
}

func (f *fakeSource) Read(buf []byte) (int, error) {
	if len(f.packets) == 0 {
		if f.quiet++; f.quiet > 3 {
			return 0, os.ErrClosed
		}
		return 0, errQuiet
	}
	packet := f.packets[0]
	f.packets = f.packets[1:]
	return copy(buf, packet), nil
}

func (f *fakeSource) Close() error { f.closed = true; return nil }

func TestRunReadsThroughQuietStretches(t *testing.T) {
	source := &fakeSource{packets: [][]byte{nil, ipv4TCP([4]byte{10, 8, 0, 7}, 443, clientHello("example.org"))}}
	var seen []Sighting
	w := New("wg0", func(s Sighting) { seen = append(seen, s) })
	w.SetOpener(func(string) (PacketSource, error) { return source, nil })
	w.Run(context.Background())

	if len(seen) != 1 || seen[0].Domain != "example.org" {
		t.Fatalf("наблюдение просрано: %+v", seen)
	}
	if !source.closed {
		t.Fatal("сокет не закрыли")
	}
}

func TestRunLeavesWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := &fakeSource{}
	w := New("wg0", nil)
	w.SetOpener(func(string) (PacketSource, error) { return source, nil })
	w.Run(ctx)
	if !source.closed {
		t.Fatal("сокет не закрыли")
	}
}
