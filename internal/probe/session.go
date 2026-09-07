package probe

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/dialpick"
)

// Config is what a vantage point needs to reach the head
type Config struct {
	HeadEndpoint string
	ProbeID      string
	Region       string
	ISP          string
	ASN          string
	Version      string

	// Dial supplies the transport, keyed the same way an agent's is
	Dial func(ctx context.Context, endpoint string) (*grpc.ClientConn, error)
	// Measure runs one target. Injected so the loop can be tested without an
	// Xray build on the machine running the tests
	Measure func(ctx context.Context, target *fedpb.ProbeTarget) *fedpb.ProbeReport

	// RelayPort - порт, на котором ноды пускают зонда к башке. Ноль выключает
	// запасные пути целиком
	RelayPort int
	// RelayCache - файл, где лежат узнанные пути. Без него рестарт зонда стирает
	// знание о нодах, и он снова упирается в закрытый адрес башки
	RelayCache string
	// Relays - пути, заданные руками. Нужны на холодный старт: узнать ноды из
	// задания можно только по сессии, а её может не быть вовсе
	Relays []string
}

// heartbeatInterval keeps the head aware the vantage point is alive between
// measurement rounds, which are minutes apart
const heartbeatInterval = 30 * time.Second

// minUsefulSession - сколько сессия обязана прожить, чтобы адрес считался
// рабочим. Круг замеров идёт минутами, так что сессия короче пяти минут не
// довозит вообще ничего, сколько бы раз она ни вставала
const minUsefulSession = 5 * time.Minute

// firstFrameTimeout - сколько ждём от башки первое слово. Она отвечает заданием
// сразу, так что молчание дольше этого означает дыру на пути, а не задумчивость
const firstFrameTimeout = 25 * time.Second

// errSilentHead - соединение встало, а башка молчит. Адрес бракуем и идём
// дальше по списку
var errSilentHead = errors.New("probe: the head is silent, the address looks like a black hole")

// connectTimeout - сколько ждём готовности канала. Живая башка отвечает за
// доли секунды даже из другой страны
const connectTimeout = 15 * time.Second

// waitReady держит паузу, пока канал не станет рабочим. Возвращает false, когда
// ждать надоело
func waitReady(ctx context.Context, conn *grpc.ClientConn, timeout time.Duration) bool {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return true
		}
		if !conn.WaitForStateChange(deadline, state) {
			return false
		}
	}
}

// Run keeps a probe session open until ctx ends, reconnecting with backoff
func Run(ctx context.Context, cfg Config) error {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	picker := dialpick.New(cfg.HeadEndpoint)
	// Заданные руками идут первыми: они точно живые, их выбирал человек
	known := append([]string(nil), cfg.Relays...)
	known = append(known, loadRelays(cfg.RelayCache)...)
	if relays := dedupRelays(known); len(relays) > 0 {
		picker.SetRelays(relays)
		log.Printf("probe: holding %d fallback paths through nodes", len(relays))
	}
	for {
		err := runOnce(ctx, cfg, picker)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("probe: session ended: %v (retrying in %s)", err, backoff)
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff + jitter):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		backoff = 2 * time.Second
	}
}

func runOnce(ctx context.Context, cfg Config, picker *dialpick.Picker) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Имя башки стоит за балансировщиком, и тот иногда отдаёт узел, до
	// которого из этой сети не достучаться. Перебираем адреса сами, а рабочий
	// запоминаем, пока балансировщик его отдаёт
	endpoint := picker.Next(ctx)
	// Пишем КУДА идём: без этой строки молчащий зонд неотличим от мёртвого, и
	// понять, на каком адресе он залип, можно только гаданием
	log.Printf("probe: dialing %s", endpoint)
	conn, err := cfg.Dial(ctx, endpoint)
	if err != nil {
		picker.Failed(endpoint)
		return err
	}
	defer func() { _ = conn.Close() }()

	// Ждём, пока канал реально встанет.
	//
	// Заблокированный адрес принимает TCP и молчит, а gRPC на это готов ждать
	// сколько угодно: соединение он считает устанавливающимся и терпеливо
	// ретраит, пока ядро не отвалится по своему таймауту минут через десять. Всё
	// это время зонд не меряет НИХУЯ и до нод не доходит
	if !waitReady(ctx, conn, connectTimeout) {
		picker.Failed(endpoint)
		return errSilentHead
	}

	stream, err := fedpb.NewFederationClient(conn).ProbeSession(ctx)
	if err != nil {
		picker.Failed(endpoint)
		return err
	}
	// Адрес считается рабочим не по факту дозвона, а по прожитой сессии.
	//
	// Дозвониться можно куда угодно: соединение встаёт, башка пишет "зонд на
	// связи", а через полторы минуты его рвут по дороге. Раз дозвон засчитан за
	// удачу, зонд липнет к этому адресу вечно и не пробует остальные - именно
	// так он и простоял восемь часов, ни разу ничего не померив
	opened := time.Now()
	defer func() {
		if time.Since(opened) < minUsefulSession {
			picker.Failed(endpoint)
			return
		}
		picker.Worked(endpoint)
	}()
	if err := stream.Send(&fedpb.ProbeFrame{Frame: &fedpb.ProbeFrame_Hello{Hello: &fedpb.ProbeHello{
		ProbeId: cfg.ProbeID, Region: cfg.Region, Isp: cfg.ISP,
		Asn: cfg.ASN, AgentVersion: cfg.Version,
	}}}); err != nil {
		return err
	}

	tasks := make(chan *fedpb.ProbeTask, 1)
	errs := make(chan error, 1)
	go func() {
		for {
			task, err := stream.Recv()
			if err != nil {
				errs <- err
				return
			}
			// Only the newest target list matters: an older one measures nodes
			// that may already have left rotation
			select {
			case <-tasks:
			default:
			}
			tasks <- task
		}
	}()

	// Дедлайн на первый ответ башки.
	//
	// Заблокированный адрес ведёт себя не как закрытый, а как чёрная дыра: TCP
	// встаёт, пакеты уходят и не возвращаются, и стрим висит молча ВЕЧНО. Без
	// этого таймера зонд намертво залипает на первом же таком адресе и до нод не
	// доходит никогда
	greeted := time.NewTimer(firstFrameTimeout)
	defer greeted.Stop()

	beat := time.NewTicker(heartbeatInterval)
	defer beat.Stop()
	var round <-chan time.Time
	var current *fedpb.ProbeTask
	measuring := make(chan []*fedpb.ProbeReport, 1)
	busy := false
	// Отчёты уходят по мере готовности: круг из нескольких целей с таймаутами
	// идёт минутами, и пачкой в конце результат первой цели ждал бы все
	// остальные
	ready := make(chan *fedpb.ProbeReport, 8)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case <-greeted.C:
			return errSilentHead
		case task := <-tasks:
			greeted.Stop()
			current = task
			// Что меряем, через то и можем дозвониться: ноды доступны из страны
			// по определению, а адрес башки закрывают
			rememberRelays(cfg, picker, task)
			if !busy {
				busy = true
				go func(t *fedpb.ProbeTask) { measuring <- measureAll(ctx, cfg, t, ready) }(current)
			}
		case report := <-ready:
			if err := stream.Send(&fedpb.ProbeFrame{
				Frame: &fedpb.ProbeFrame_Report{Report: report},
			}); err != nil {
				return err
			}
		case <-measuring:
			busy = false
			round = time.After(intervalOf(current))
		case <-round:
			if current != nil && !busy {
				busy = true
				go func(t *fedpb.ProbeTask) { measuring <- measureAll(ctx, cfg, t, ready) }(current)
			}
		case <-beat.C:
			if err := stream.Send(&fedpb.ProbeFrame{Frame: &fedpb.ProbeFrame_Heartbeat{
				Heartbeat: &fedpb.Heartbeat{UnixMs: time.Now().UnixMilli()},
			}}); err != nil {
				return err
			}
		}
	}
}

// retryPause - пауза перед повторной попыткой упавшего замера
const retryPause = 3 * time.Second

// measureAll walks the target list one at a time. Serially on purpose: two
// measurements at once compete for the vantage point's own uplink and both come
// out looking shaped.
//
// Упавший замер повторяется один раз: обрыв соединения случается и на рабочем
// транспорте, а до следующего круга целых пять минут, и всё это время нода
// числилась бы недоступной из-за одного EOF
func measureAll(ctx context.Context, cfg Config, task *fedpb.ProbeTask, ready chan<- *fedpb.ProbeReport) []*fedpb.ProbeReport {
	out := make([]*fedpb.ProbeReport, 0, len(task.GetTargets()))
	for _, target := range task.GetTargets() {
		if ctx.Err() != nil {
			return out
		}
		if isIPv6(target.GetHost()) && !haveIPv6() {
			// У точки наблюдения нет исходящего IPv6, и её "не дозвонился" сказал
			// бы про её собственную сеть, а не про ноду. Молчим вместо лжи
			continue
		}
		report := cfg.Measure(ctx, target)
		if report != nil && !report.GetHandshakeOk() {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(retryPause):
			}
			if second := cfg.Measure(ctx, target); second != nil && second.GetHandshakeOk() {
				report = second
			}
		}
		out = append(out, report)
		select {
		case ready <- report:
		case <-ctx.Done():
			return out
		}
	}
	return out
}

func intervalOf(task *fedpb.ProbeTask) time.Duration {
	if secs := task.GetIntervalSeconds(); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 5 * time.Minute
}

// ipv6Once считает связность один раз за запуск: она не меняется под ногами, а
// проверять её перед каждым замером значит ходить наружу впустую
var (
	ipv6Once sync.Once
	ipv6Up   bool
)

func haveIPv6() bool {
	ipv6Once.Do(func() {
		conn, err := net.DialTimeout("udp6", "[2001:4860:4860::8888]:53", 2*time.Second)
		if err != nil {
			return
		}
		_ = conn.Close()
		ipv6Up = true
	})
	return ipv6Up
}

// isIPv6 отличает адрес от имени: имя резолвится сетью и в обе семьи, а голый
// IPv6 меряется только оттуда, где IPv6 есть
func isIPv6(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	addr := net.ParseIP(host)
	return addr != nil && addr.To4() == nil
}
