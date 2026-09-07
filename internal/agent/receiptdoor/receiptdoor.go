// Package receiptdoor принимает расписки от клиентов, сидящих в туннеле.
//
// Нужен там, где до панели снаружи не достучаться: в белом списке приложение
// само вне туннеля, панель у провайдера закрыта, и единственный, до кого клиент
// точно дотягивается, это нода, через которую он и сидит.
//
// Наружу дверь не торчит: слушаем петлю (туда Xray заворачивает по правилу) и
// адрес ноды внутри wg (туда стучатся клиенты VK TURN). Ни один порт на
// донорской машине от этого не открывается
package receiptdoor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// maxBody - потолок на запрос. Расписка это триста байт, батч в мегабайт уже
// значит, что кто-то развлекается
const maxBody = 1 << 20

// maxQueued - сколько расписок держим до отправки башке. Дальше НОВЫЕ идут
// нахуй, а не вытесняют лежащие: иначе любой сосед по петле забивает очередь
// мусором и выбивает из неё чужие честные подписи
const maxQueued = 4096

// maxPerRequest - сколько расписок в одном запросе. Клиент копит пятиминутками
// за неделю, больше сотни ему взять неоткуда
const maxPerRequest = 256

// rateWindow и rateBurst - сколько запросов с одного адреса терпим.
//
// Дверь слушает петлю ноды и адрес внутри туннеля, то есть постучать может любой
// процесс на машине донора и любой сосед по туннелю. Подделать расписку никто из
// них не может, а вот долбить дверь до посинения - запросто
const (
	rateWindow = time.Minute
	rateBurst  = 30
)

// Receipt - то, что присылает клиент. Формат тот же, что панель принимает по
// HTTP, чтобы приложению не собирать вторую версию тела
type Receipt struct {
	ClientID        string `json:"client_id"`
	NodeID          string `json:"node_id"`
	Transport       string `json:"transport"`
	WindowStartUnix int64  `json:"window_start_unix"`
	WindowEndUnix   int64  `json:"window_end_unix"`
	PayloadUpBytes  uint64 `json:"payload_up_bytes"`
	PayloadDown     uint64 `json:"payload_down_bytes"`
	Nonce           string `json:"nonce"`
	Signature       string `json:"signature"`
}

// Door - сама дверь
type Door struct {
	mu     sync.Mutex
	queued []*fedpb.TrafficReceipt
	log    func(string, ...any)
	// seen схлопывает повторы по паре человек-nonce: клиент шлёт одно и то же
	// всеми путями сразу, лишь бы доехало хоть чем-то
	seen map[string]time.Time
	// hits - сколько раз стучали с адреса за окно
	hits map[string]*rateCounter
	now  func() time.Time
}

type rateCounter struct {
	count int
	since time.Time
}

func New() *Door {
	return &Door{seen: map[string]time.Time{}, hits: map[string]*rateCounter{}, now: time.Now}
}

// SetLogger включает журнал
func (d *Door) SetLogger(fn func(string, ...any)) { d.log = fn }

// Drain отдаёт накопленное и очищает очередь. Зовёт сессия агента
func (d *Door) Drain() []*fedpb.TrafficReceipt {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queued) == 0 {
		return nil
	}
	out := d.queued
	d.queued = nil
	return out
}

// Serve слушает адреса, пока жив ctx. Пустой список означает, что дверь не
// нужна
func (d *Door) Serve(ctx context.Context, addresses []string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/receipts", d.handle)
	for _, address := range addresses {
		if address == "" {
			continue
		}
		go d.listen(ctx, address, mux)
	}
}

func (d *Door) listen(ctx context.Context, address string, handler http.Handler) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		if d.log != nil {
			d.log("receiptdoor: %s does not listen: %v", address, err)
		}
		return
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && d.log != nil {
		d.log("receiptdoor: %s dropped: %v", address, err)
	}
}

func (d *Door) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	if !d.allow(r.RemoteAddr) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	var body struct {
		Receipts []Receipt `json:"receipts"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	// Подпись не проверяем: ключей клиентов на ноде нет и быть не должно. Врать
	// тут бессмысленно, всё решает башка, а нода лишь несёт байты
	if len(body.Receipts) > maxPerRequest {
		body.Receipts = body.Receipts[:maxPerRequest]
	}
	accepted := d.enqueue(body.Receipts)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"queued": accepted})
}

func (d *Door) enqueue(items []Receipt) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	accepted := 0
	for _, item := range items {
		if len(d.queued) >= maxQueued {
			// Место кончилось. Отбиваем новое, а не выкидываем лежащее: старые
			// расписки уже дождались своей очереди и терять их незачем
			break
		}
		signature, err := decodeSignature(item.Signature)
		if err != nil || item.ClientID == "" || item.Nonce == "" {
			continue
		}
		key := item.ClientID + "|" + item.Nonce
		if last, ok := d.seen[key]; ok && now.Sub(last) < seenMemory {
			continue
		}
		d.seen[key] = now
		d.queued = append(d.queued, &fedpb.TrafficReceipt{
			ClientId: item.ClientID, NodeId: item.NodeID, Transport: item.Transport,
			WindowStartUnix: item.WindowStartUnix, WindowEndUnix: item.WindowEndUnix,
			PayloadUpBytes: item.PayloadUpBytes, PayloadDownBytes: item.PayloadDown,
			Nonce: item.Nonce, Signature: signature,
		})
		accepted++
	}
	return accepted
}

func decodeSignature(raw string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(raw)
}

// seenMemory - как долго помним уже принятую пару человек-nonce
const seenMemory = time.Hour

// allow пропускает не больше rateBurst запросов с адреса за окно
func (d *Door) allow(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	counter, ok := d.hits[host]
	if !ok || now.Sub(counter.since) > rateWindow {
		d.hits[host] = &rateCounter{count: 1, since: now}
		d.forgetStaleLocked(now)
		return true
	}
	counter.count++
	return counter.count <= rateBurst
}

// forgetStaleLocked чистит протухшее. Держит замок вызывающий
func (d *Door) forgetStaleLocked(now time.Time) {
	for host, counter := range d.hits {
		if now.Sub(counter.since) > 2*rateWindow {
			delete(d.hits, host)
		}
	}
	for key, at := range d.seen {
		if now.Sub(at) > seenMemory {
			delete(d.seen, key)
		}
	}
}
