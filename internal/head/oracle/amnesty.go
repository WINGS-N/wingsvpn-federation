package oracle

import (
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// Forgetter - хранилище, умеющее снять уже записанные наблюдения.
//
// Реализуют не все: судья остаётся рабочим и с хранилищем, которое только пишет,
// просто прощение тогда живёт до перезапуска
type Forgetter interface {
	ForgetSignals(clientID string, kind fedpb.AbuseKind, from, to time.Time) error
}

// Forgive снимает обвинения одного вида за окно, которое участник закрыл задним
// числом.
//
// Расписка, доехавшая из очереди, доказывает ровно то, за отсутствие чего его
// наказали: молчание было нашим проёбом доставки, а не его виной. Оставить минус
// значит наказать человека за то, что у нас не доехал запрос
func (j *Judge) Forgive(clientID string, kind fedpb.AbuseKind, from, to time.Time) int {
	if clientID == "" || !to.After(from) {
		return 0
	}
	j.mu.Lock()
	kept := j.signals[clientID][:0]
	forgiven := 0
	for _, s := range j.signals[clientID] {
		if s.Kind == kind && !s.Observed.Before(from) && !s.Observed.After(to) {
			forgiven++
			continue
		}
		kept = append(kept, s)
	}
	j.signals[clientID] = kept
	sink := j.sink
	j.mu.Unlock()

	if forgiven == 0 {
		return 0
	}
	// Хранилище чистим тоже: иначе Restore после перезапуска вернёт прощённое
	if forgetter, ok := sink.(Forgetter); ok && forgetter != nil {
		_ = forgetter.ForgetSignals(clientID, kind, from, to)
	}
	return forgiven
}
