// Package donations хранит вклад каждого донора с разбивкой по месяцам
package donations

import (
	"sort"
	"sync"
	"time"
)

// Month - формат ключа: YYYY-MM в UTC, чтобы один и тот же трафик не попадал
// в разные месяцы у людей из разных часовых поясов
func Month(at time.Time) string { return at.UTC().Format("2006-01") }

// Store - куда уходят закрытые дельты. Интерфейс, потому что башка без
// Postgres тоже ведёт историю
type Store interface {
	Add(donorID, month string, bytes uint64) error
	History(donorID string, months int) ([]Entry, error)
}

// Entry - один месяц одного донора
type Entry struct {
	Month string
	Bytes uint64
}

// Recorder копит дельты в памяти: писать сразу значит UPDATE на каждый сэмпл
// ради числа, которое читают раз в день
type Recorder struct {
	mu      sync.Mutex
	pending map[string]map[string]uint64
	store   Store
}

// New оборачивает хранилище
func New(store Store) *Recorder {
	return &Recorder{pending: make(map[string]map[string]uint64), store: store}
}

// Add добавляет одну дельту. Зовётся из потока сэмплов, поэтому базы не касается
func (r *Recorder) Add(donorID string, at time.Time, bytes uint64) {
	if donorID == "" || bytes == 0 {
		return
	}
	month := Month(at)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[month] == nil {
		r.pending[month] = make(map[string]uint64)
	}
	r.pending[month][donorID] += bytes
}

// Flush записывает всё накопленное. Неудачная запись оставляет байты в
// очереди, их унесёт следующий сброс
func (r *Recorder) Flush() error {
	r.mu.Lock()
	batch := r.pending
	r.pending = make(map[string]map[string]uint64)
	r.mu.Unlock()

	var failed error
	for month, donors := range batch {
		for donor, bytes := range donors {
			if err := r.store.Add(donor, month, bytes); err != nil {
				failed = err
				r.mu.Lock()
				if r.pending[month] == nil {
					r.pending[month] = make(map[string]uint64)
				}
				r.pending[month][donor] += bytes
				r.mu.Unlock()
			}
		}
	}
	return failed
}

// Run сбрасывает по таймеру, пока не кончится ctx
func (r *Recorder) Run(done <-chan struct{}, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			_ = r.Flush()
			return
		case <-ticker.C:
			_ = r.Flush()
		}
	}
}

// History возвращает последние месяцы донора, свежие первыми. Незаписанное
// подмешивается, чтобы текущий месяц не отставал на минуту
func (r *Recorder) History(donorID string, months int) ([]Entry, error) {
	if months <= 0 {
		months = 12
	}
	stored, err := r.store.History(donorID, months)
	if err != nil {
		return nil, err
	}
	byMonth := make(map[string]uint64, len(stored))
	for _, e := range stored {
		byMonth[e.Month] = e.Bytes
	}
	r.mu.Lock()
	for month, donors := range r.pending {
		byMonth[month] += donors[donorID]
	}
	r.mu.Unlock()

	out := make([]Entry, 0, len(byMonth))
	for month, bytes := range byMonth {
		out = append(out, Entry{Month: month, Bytes: bytes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Month > out[j].Month })
	if len(out) > months {
		out = out[:months]
	}
	return out, nil
}

// MemStore - запасной вариант для башки без Postgres
type MemStore struct {
	mu   sync.Mutex
	rows map[string]map[string]uint64
}

// NewMemStore создаёт пустое хранилище в памяти
func NewMemStore() *MemStore {
	return &MemStore{rows: make(map[string]map[string]uint64)}
}

// Add копит один месяц
func (m *MemStore) Add(donorID, month string, bytes uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[donorID] == nil {
		m.rows[donorID] = make(map[string]uint64)
	}
	m.rows[donorID][month] += bytes
	return nil
}

// History возвращает свежие месяцы первыми
func (m *MemStore) History(donorID string, months int) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entry, 0, len(m.rows[donorID]))
	for month, bytes := range m.rows[donorID] {
		out = append(out, Entry{Month: month, Bytes: bytes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Month > out[j].Month })
	if len(out) > months {
		out = out[:months]
	}
	return out, nil
}
