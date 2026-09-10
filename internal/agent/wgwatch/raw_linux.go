//go:build linux

package wgwatch

import (
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// readTimeout - на сколько recvfrom засыпает без пакетов. Через него же
// проверяется, не пора ли съёбывать, иначе горутина висела бы на тихом
// интерфейсе до первого байта
const readTimeout = time.Second

// helloFilter - cBPF, который ядро крутит ДО того, как скопировать пакет нам.
//
// Без него AF_PACKET клонирует КАЖДЫЙ пакет туннеля и будит нас на каждый,
// то есть на гигабите это под 80 тысяч сисколлов в секунду ради пары
// рукопожатий - полный пиздец на чужом сервере. Фильтр оставляет только TCP на
// 443 с первым байтом нагрузки 0x16, а это и есть ClientHello: одна штука на
// сессию вместо всего потока.
//
// IPv6 отсекается сознательно: пиры получают /32 из 10.67.66.0/24, и внутри
// туннеля шестёрки нет вообще.
//
// Собрано командой
// tcpdump -y RAW -dd 'tcp dst port 443 and tcp[((tcp[12]&0xf0)>>2)] = 22'
// Смещения идут от IP-заголовка, потому что wg это L3 и канального заголовка
// на нём нет
var helloFilter = []unix.SockFilter{
	{Code: 0x30, K: 0x00000000}, // ldb [0], версия и длина заголовка
	{Code: 0x54, K: 0x000000f0}, // and #0xf0
	{Code: 0x15, Jt: 18, K: 0x00000060},
	{Code: 0x30, K: 0x00000000},
	{Code: 0x54, K: 0x000000f0},
	{Code: 0x15, Jf: 15, K: 0x00000040},
	{Code: 0x30, K: 0x00000009}, // ldb [9], протокол
	{Code: 0x15, Jf: 13, K: 0x00000006},
	{Code: 0x28, K: 0x00000006}, // ldh [6], флаги и смещение фрагмента
	{Code: 0x45, Jt: 11, K: 0x00001fff},
	{Code: 0xb1, K: 0x00000000}, // ldxb 4*([0]&0xf)
	{Code: 0x48, K: 0x00000002}, // ldh [x+2], порт назначения
	{Code: 0x15, Jf: 8, K: 0x000001bb},
	{Code: 0x50, K: 0x0000000c}, // ldb [x+12], смещение данных TCP
	{Code: 0x54, K: 0x000000f0},
	{Code: 0x74, K: 0x00000002},
	{Code: 0x0c, K: 0x00000000}, // add x, длина обоих заголовков
	{Code: 0x07, K: 0x00000000}, // tax
	{Code: 0x50, K: 0x00000000}, // ldb [x], первый байт нагрузки
	{Code: 0x15, Jf: 1, K: 0x00000016},
	{Code: 0x06, K: maxPacket}, // берём, но не больше буфера
	{Code: 0x06, K: 0x00000000},
}

// openRaw открывает сырой сокет на интерфейсе.
//
// AF_PACKET с ETH_P_IP: wg это L3-устройство, канального заголовка на нём нет,
// и в сокет приходят сразу IP-пакеты.
//
// Дескриптор читается напрямую, без net.FilePacketConn: стандартная библиотека
// заворачивает только AF_INET, AF_INET6 и AF_UNIX, а на AF_PACKET высирает
// "protocol not supported"
func openRaw(iface string) (PacketSource, error) {
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		int(htons(unix.ETH_P_IP)))
	if err != nil {
		return nil, err
	}
	// Фильтр вешаем ДО bind: между этими двумя вызовами в очередь успевает
	// налететь нефильтрованное, и обратный порядок означает пачку чужих пакетов
	// в буфере на старте
	program := unix.SockFprog{Len: uint16(len(helloFilter)), Filter: &helloFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  link.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	timeout := unix.NsecToTimeval(int64(readTimeout))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &rawConn{fd: fd}, nil
}

// rawConn - сокет AF_PACKET
type rawConn struct{ fd int }

func (c *rawConn) Read(buf []byte) (int, error) {
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, errQuiet
		}
		if errors.Is(err, unix.EBADF) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	return n, nil
}

func (c *rawConn) Close() error { return unix.Close(c.fd) }

// htons переставляет байты под сетевой порядок, которого ждёт AF_PACKET
func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
