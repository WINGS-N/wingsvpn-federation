package donations

import (
	"errors"
	"testing"
	"time"
)

func TestRecorderFoldsAndFlushes(t *testing.T) {
	store := NewMemStore()
	rec := New(store)
	june := time.Date(2026, 6, 30, 23, 0, 0, 0, time.UTC)
	july := time.Date(2026, 7, 1, 1, 0, 0, 0, time.UTC)

	rec.Add("admin-1", june, 100)
	rec.Add("admin-1", june, 50)
	rec.Add("admin-1", july, 7)
	rec.Add("admin-2", july, 3)

	// Ещё не сброшено в хранилище, но донор уже должен видеть текущий месяц
	got, err := rec.History("admin-1", 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Month != "2026-07" || got[0].Bytes != 7 || got[1].Bytes != 150 {
		t.Fatalf("pending history wrong: %+v", got)
	}

	if err := rec.Flush(); err != nil {
		t.Fatal(err)
	}
	got, err = rec.History("admin-1", 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Bytes != 150 {
		t.Fatalf("flushed history wrong: %+v", got)
	}
	if other, _ := rec.History("admin-2", 12); len(other) != 1 || other[0].Bytes != 3 {
		t.Fatalf("donors leaked into each other: %+v", other)
	}
}

type brokenStore struct{ MemStore }

func (b *brokenStore) Add(string, string, uint64) error { return errors.New("db down") }

// Байты, не доехавшие до базы, обязаны остаться в очереди: иначе падение базы
// на минуту тихо стирает месяц донора
func TestFlushKeepsBytesWhenStoreFails(t *testing.T) {
	rec := New(&brokenStore{})
	rec.Add("admin-1", time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC), 42)
	if err := rec.Flush(); err == nil {
		t.Fatal("a failed write must be reported")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.pending["2026-07"]["admin-1"] != 42 {
		t.Fatalf("bytes dropped on failure: %+v", rec.pending)
	}
}
