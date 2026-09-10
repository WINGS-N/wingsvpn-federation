// Package dialpick выбирает, по какому адресу дозваниваться, когда имя за
// балансировщиком отдаёт разные ответы.
//
// Балансировщик иногда подсовывает узел, недоступный из этой сети: правило
// геолокации отрабатывает по резолверу, а не по нам, да и здоровье пула у него
// моргает. Ложиться на каждый такой чих нельзя.
//
// При этом решение балансировщика уважается: держимся мы только за тот адрес,
// который он ПРОДОЛЖАЕТ отдавать. Убрал из пула - отпускаем и идём за свежим,
// потому что про переезд и обслуживание он знает, а мы нет
package dialpick

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// recheckEvery - как часто перепроверяем, отдаёт ли балансировщик наш адрес.
// Между проверками ходим по нему без лишних вопросов
const recheckEvery = 10 * time.Minute

// lookupTimeout - сколько ждём DNS. Резолвер под боком, и дольше он думает
// только когда сам лёг
const lookupTimeout = 5 * time.Second

// Resolver - откуда берём адреса имени. Отдельно ради тестов
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Picker помнит, какой адрес реально работал
type Picker struct {
	endpoint string
	resolver Resolver
	now      func() time.Time

	mu     sync.Mutex
	sticky string
	since  time.Time
	// tried - что уже пробовали в текущем заходе, чтобы не топтаться на одном
	tried map[string]bool
	// relays - запасные пути через ноды, целиком в виде host:port.
	//
	// Прямой адрес башки блокируют, и тогда ходить по её же именам бесполезно,
	// сколько их ни резолвь: они все ведут в одну заблокированную точку. Нода
	// доступна по определению - в этом её работа
	relays []string
}

// New строит выбор для одного адреса вида host:port
func New(endpoint string) *Picker {
	return &Picker{
		endpoint: endpoint,
		resolver: net.DefaultResolver,
		now:      time.Now,
		tried:    map[string]bool{},
	}
}

// SetResolver подменяет резолвер
func (p *Picker) SetResolver(r Resolver) { p.resolver = r }

// Next отдаёт следующий адрес для попытки.
//
// Пока держится удачный, отдаётся он. Когда его отбраковали, идём по остальным
// адресам имени и возвращаем непробованный
func (p *Picker) Next(ctx context.Context) string {
	host, port, err := net.SplitHostPort(p.endpoint)
	if err != nil || net.ParseIP(host) != nil {
		// Имя не разобрать или это уже адрес, выбирать не из чего
		return p.endpoint
	}

	p.mu.Lock()
	sticky, since := p.sticky, p.since
	p.mu.Unlock()
	if sticky != "" && p.now().Sub(since) < recheckEvery {
		return net.JoinHostPort(sticky, port)
	}

	// Резолв с дедлайном: висящий DNS не должен подвешивать весь перебор, иначе
	// зонд молча стоит и не пробует ни одного адреса
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := p.resolver.LookupHost(lookupCtx, host)
	if err != nil || len(addrs) == 0 {
		// Резолв не удался: лучше пойти по последнему рабочему, чем никуда
		if sticky != "" {
			return net.JoinHostPort(sticky, port)
		}
		return p.endpoint
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Балансировщик всё ещё отдаёт наш адрес, значит он в пуле и держаться за
	// него честно. Перестал отдавать - отпускаем, ему виднее
	if sticky != "" {
		for _, addr := range addrs {
			if addr == sticky {
				p.since = p.now()
				return net.JoinHostPort(sticky, port)
			}
		}
		p.sticky = ""
	}
	for _, addr := range addrs {
		if !p.tried[addr] {
			p.tried[addr] = true
			return net.JoinHostPort(addr, port)
		}
	}
	// Прямые адреса кончились - идём через ноды. Это не запасной аэродром на
	// крайний случай, а нормальный путь: башку закрывают целиком, и тогда все
	// её адреса мертвы одинаково
	for _, relay := range p.relays {
		if !p.tried[relay] {
			p.tried[relay] = true
			return relay
		}
	}
	// Круг пройден целиком, начинаем заново: адреса могли ожить, да и пул у
	// балансировщика меняется от запроса к запросу
	p.tried = map[string]bool{addrs[0]: true}
	return net.JoinHostPort(addrs[0], port)
}

// SetRelays задаёт запасные пути через ноды. Зонд узнаёт их из заданий на
// замер: что он меряет, через то и может дозвониться
func (p *Picker) SetRelays(relays []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.relays = append([]string(nil), relays...)
}

// Worked отмечает адрес как рабочий, за него и держимся
func (p *Picker) Worked(endpoint string) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sticky = host
	p.since = p.now()
	p.tried = map[string]bool{}
}

// Failed бракует адрес: следующая попытка пойдёт на другой
func (p *Picker) Failed(endpoint string) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sticky == host {
		p.sticky = ""
	}
	p.tried[host] = true
}

// Sticky - адрес, за который держимся. Пусто, когда рабочего ещё нет
func (p *Picker) Sticky() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sticky
}

// HostOf вытаскивает хост из endpoint, не спотыкаясь о кривой ввод
func HostOf(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return strings.TrimSpace(endpoint)
	}
	return host
}
