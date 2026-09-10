package fedserver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Башке могут прикрыть адрес: она сидит в одном месте, ходит наружу постоянно и
// светится куда больше, чем любая нода. Ноды при этом раскиданы по разным
// сетям, и через них видно то, что башке уже нихуя не видно.
//
// Поэтому у неё есть запасной путь: попросить ноду сходить за телом вместо
// себя. Нода в содержимое не вникает, она тут почтальон

// fetchWait - сколько ждём ответа ноды. Дольше держать бессмысленно: у нас
// целый флот, проще спросить следующую
const fetchWait = 30 * time.Second

// ErrNoFetchers - спросить некого, ни одной живой ноды
var ErrNoFetchers = errors.New("fedserver: no node can fetch")

// pending - ожидание одного ответа
type pending struct {
	mu      sync.Mutex
	waiting map[string]chan *fedpb.FetchResult
}

func newPending() *pending { return &pending{waiting: map[string]chan *fedpb.FetchResult{}} }

func (p *pending) add(id string) chan *fedpb.FetchResult {
	ch := make(chan *fedpb.FetchResult, 1)
	p.mu.Lock()
	p.waiting[id] = ch
	p.mu.Unlock()
	return ch
}

func (p *pending) drop(id string) {
	p.mu.Lock()
	delete(p.waiting, id)
	p.mu.Unlock()
}

// deliver отдаёт ответ тому, кто его ждёт. Ответ на просроченный запрос
// выбрасывается молча: ждать его уже некому
func (p *pending) deliver(result *fedpb.FetchResult) {
	p.mu.Lock()
	ch, ok := p.waiting[result.GetId()]
	delete(p.waiting, result.GetId())
	p.mu.Unlock()
	if ok {
		ch <- result
	}
}

// FetchVia просит ноды сходить за телом, пока одна из них не принесёт.
//
// Обходим по очереди: нода могла отвалиться между проверкой и отправкой, а у
// продавца может быть закрыт доступ из конкретной страны - тогда следующая
// нода в другой стране принесёт то же самое без вопросов
func (s *Server) FetchVia(ctx context.Context, url string, headers map[string]string, maxBytes uint32) ([]byte, error) {
	nodes := s.Connected()
	if len(nodes) == 0 {
		return nil, ErrNoFetchers
	}
	var lastErr error
	for _, nodeID := range nodes {
		body, err := s.fetchFrom(ctx, nodeID, url, headers, maxBytes)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrNoFetchers
	}
	return nil, lastErr
}

func (s *Server) fetchFrom(ctx context.Context, nodeID, url string, headers map[string]string, maxBytes uint32) ([]byte, error) {
	id := fmt.Sprintf("%s-%d", nodeID, time.Now().UnixNano())
	ch := s.pending.add(id)
	defer s.pending.drop(id)

	err := s.Push(nodeID, &fedpb.HeadFrame{Frame: &fedpb.HeadFrame_Fetch{Fetch: &fedpb.FetchRequest{
		Id:             id,
		Url:            url,
		Headers:        headers,
		TimeoutSeconds: uint32(fetchWait.Seconds()),
		MaxBytes:       maxBytes,
	}}})
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(fetchWait):
		return nil, fmt.Errorf("fedserver: %s did not answer in time", nodeID)
	case result := <-ch:
		if result.GetError() != "" {
			return nil, errors.New(result.GetError())
		}
		if status := result.GetStatus(); status != 0 && status != 200 {
			return nil, fmt.Errorf("fedserver: %s got status %d", nodeID, status)
		}
		return result.GetBody(), nil
	}
}
