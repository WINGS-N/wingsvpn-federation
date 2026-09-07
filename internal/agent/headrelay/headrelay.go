// Package headrelay пускает зонд к башке через ноду.
//
// Адрес башки блокируют, и зонд, сидящий в стране, до неё просто не дотягивается:
// соединение встаёт, живёт полторы минуты и его рвут по дороге. А ноды доступны
// по определению - в этом их работа, иначе через них не ходили бы люди.
//
// Нода тут ТУПАЯ ТРУБА и ничего больше. Она гоняет байты и не понимает в них ни
// хуя: зонд говорит с башкой своим ключом, которого у флота нет. Подменить отчёт
// о достижимости нода не может, даже если очень захочет - а хотеть ей есть чего,
// это же её собственную скорость зонд и меряет
package headrelay

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// dialTimeout - сколько ждём саму башку. Она за границей, так что с запасом
const dialTimeout = 15 * time.Second

// idleTimeout - сколько держим тишину, прежде чем закрыть. Зонд шлёт keepalive
// каждые двадцать секунд, поэтому по-настоящему молчащее соединение брошено
const idleTimeout = 3 * time.Minute

// maxConns - сколько ретрансляций держим разом. Зондов единицы, и сотня
// соединений тут означала бы, что нашу трубу пользуют не по назначению
const maxConns = 16

// Relay слушает свой порт и гоняет байты к башке
type Relay struct {
	listen string
	head   string
	log    func(string, ...any)

	mu    sync.Mutex
	conns int
}

func New(listen, head string, log func(string, ...any)) *Relay {
	return &Relay{listen: listen, head: head, log: log}
}

// Run держит слушатель, пока жив ctx
func (r *Relay) Run(ctx context.Context) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", r.listen)
	if err != nil {
		if r.log != nil {
			r.log("headrelay: the listener did not start: %v", err)
		}
		return
	}
	defer func() { _ = ln.Close() }()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	if r.log != nil {
		r.log("headrelay: %s forwards probes to the head %s", r.listen, r.head)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !r.take() {
			// Труба занята: молча закрываем, а не копим соединения до упора
			_ = conn.Close()
			continue
		}
		go func() {
			defer r.give()
			r.pipe(ctx, conn)
		}()
	}
}

func (r *Relay) take() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns >= maxConns {
		return false
	}
	r.conns++
	return true
}

func (r *Relay) give() {
	r.mu.Lock()
	r.conns--
	r.mu.Unlock()
}

// pipe сводит два соединения и качает байты, пока одно не умрёт
func (r *Relay) pipe(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()
	dialer := net.Dialer{Timeout: dialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", r.head)
	if err != nil {
		if r.log != nil {
			r.log("headrelay: the head did not answer: %v", err)
		}
		return
	}
	defer func() { _ = upstream.Close() }()

	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				if err != io.EOF && r.log != nil {
					// Обрыв это норма, а не поломка: зонд уходит и приходит
					r.log("headrelay: the pipe closed: %v", err)
				}
				return
			}
		}
	}
	go copyOne(upstream, client)
	go copyOne(client, upstream)

	select {
	case <-done:
	case <-ctx.Done():
	}
}
