// Package wgwatch смотрит, куда ходят клиенты VK TURN.
//
// У релея нет ни sniffing, ни access-лога, он гоняет UDP, внутри которого
// WireGuard, и по нему хуй что поймёшь. Зато сам WireGuard терминируется ядром
// прямо на ноде, и с wg-интерфейса выходит уже расшифрованный трафик - обычные
// IP-пакеты, а в них TLS-рукопожатия.
//
// Оттуда и берём SNI с отпечатком, тем же парсером, что стоит в ядре для Xray.
// Привязка к человеку честная: у каждого пира свой /32 в allowed_ips, и ядро
// само не пускает его слать пакеты от чужого имени
package wgwatch

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"wingsnet.org/federation/internal/agent/tlsprint"
)

// maxPacket - потолок на пакет. ClientHello в jumbo нахуй не приезжает
const maxPacket = 2048

// Sighting - что увидели на интерфейсе
type Sighting struct {
	// Address - адрес пира внутри туннеля. По нему башка узнаёт человека
	Address string
	Domain  string
	JA3     string
	JA4     string
	At      time.Time
}

// PacketSource - откуда берутся пакеты. Свой интерфейс вместо net.PacketConn,
// сырой сокет туда не заворачивается нихуя: стандартная библиотека знает
// только AF_INET, AF_INET6 и AF_UNIX
type PacketSource interface {
	Read(buf []byte) (int, error)
	Close() error
}

// errQuiet - пакетов не было, а не поломка. Источник так говорит, что истёк
// его таймаут и цикл может оглядеться, не считая это пиздецом
var errQuiet = errors.New("wgwatch: quiet")

// Watcher читает пакеты с интерфейса
type Watcher struct {
	iface string
	open  func(iface string) (PacketSource, error)
	now   func() time.Time
	log   func(string, ...any)

	mu sync.Mutex
	// seen схлопывает повторы, одно и то же имя в окне интересно один раз
	seen map[string]time.Time
	out  func(Sighting)
}

// dedupWindow - как долго молчим про уже виденную пару адрес-домен. Браузер
// открывает десятки соединений к одному хосту, и слать эту хуйню наверх
// целиком незачем
const dedupWindow = time.Minute

func New(iface string, out func(Sighting)) *Watcher {
	return &Watcher{
		iface: iface,
		open:  openRaw,
		now:   time.Now,
		seen:  map[string]time.Time{},
		out:   out,
	}
}

// SetLogger включает журнал
func (w *Watcher) SetLogger(log func(string, ...any)) { w.log = log }

// SetOpener подменяет источник пакетов. Нужно тестам, сырому сокету подавай
// права и живой интерфейс
func (w *Watcher) SetOpener(open func(iface string) (PacketSource, error)) { w.open = open }

// Run читает интерфейс, пока жив ctx
func (w *Watcher) Run(ctx context.Context) {
	conn, err := w.open(w.iface)
	if err != nil {
		if w.log != nil {
			w.log("wgwatch: %s is unreadable: %v", w.iface, err)
		}
		return
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, maxPacket)
	for ctx.Err() == nil {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, errQuiet) {
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if w.log != nil {
				w.log("wgwatch: %s stopped reading: %v", w.iface, err)
			}
			return
		}
		w.handle(buf[:n])
	}
}

// handle разбирает один пакет
func (w *Watcher) handle(packet []byte) {
	src, payload, ok := tcpPayload(packet)
	if !ok || len(payload) == 0 {
		return
	}
	print, ok := tlsprint.Parse(payload)
	if !ok {
		return
	}
	if print.ServerName == "" && print.JA4 == "" {
		return
	}
	key := src + "|" + print.ServerName
	now := w.now()
	w.mu.Lock()
	if last, seen := w.seen[key]; seen && now.Sub(last) < dedupWindow {
		w.mu.Unlock()
		return
	}
	w.seen[key] = now
	// Протухшее чистим прямо тут, отдельный сборщик ради одной карты это
	// лишняя горутина нахуй
	for k, at := range w.seen {
		if now.Sub(at) > 2*dedupWindow {
			delete(w.seen, k)
		}
	}
	out := w.out
	w.mu.Unlock()

	if out != nil {
		out(Sighting{
			Address: src, Domain: print.ServerName,
			JA3: print.JA3Hash, JA4: print.JA4, At: now,
		})
	}
}

// tcpPayload вытаскивает адрес источника и полезную нагрузку TCP.
//
// С wg-интерфейса приходят голые IP-пакеты, канального заголовка там нет
// нихуя, это L3-устройство
func tcpPayload(packet []byte) (src string, payload []byte, ok bool) {
	if len(packet) < 20 {
		return "", nil, false
	}
	version := packet[0] >> 4
	var (
		headerLen int
		protocol  byte
		from      net.IP
	)
	switch version {
	case 4:
		headerLen = int(packet[0]&0x0f) * 4
		if headerLen < 20 || len(packet) < headerLen {
			return "", nil, false
		}
		protocol = packet[9]
		from = net.IP(packet[12:16])
	case 6:
		if len(packet) < 40 {
			return "", nil, false
		}
		headerLen = 40
		protocol = packet[6]
		from = net.IP(packet[8:24])
	default:
		return "", nil, false
	}
	if protocol != 6 {
		return "", nil, false
	}
	tcp := packet[headerLen:]
	if len(tcp) < 20 {
		return "", nil, false
	}
	offset := int(tcp[12]>>4) * 4
	if offset < 20 || len(tcp) < offset {
		return "", nil, false
	}
	// Только к 443, ClientHello ходит и по другим портам, но там его ищут
	// сканеры, а нам нужен обычный веб
	if binary.BigEndian.Uint16(tcp[2:4]) != 443 {
		return "", nil, false
	}
	return from.String(), tcp[offset:], true
}
