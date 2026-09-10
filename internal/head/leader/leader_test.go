package leader

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type fakeKube struct {
	obj     map[string]any
	version int
	// putFails изображает гонку: чужая запись прошла между чтением и записью
	putFails bool
}

func (f *fakeKube) Namespace() string { return "wingsvpn" }

func (f *fakeKube) GetRaw(_ context.Context, _ string) ([]byte, error) {
	if f.obj == nil {
		return nil, nil
	}
	return json.Marshal(f.obj)
}

func (f *fakeKube) PutRaw(_ context.Context, _ string, manifest map[string]any) ([]byte, error) {
	if f.putFails {
		return nil, errConflict{}
	}
	f.store(manifest)
	return nil, nil
}

func (f *fakeKube) PostRaw(_ context.Context, _ string, manifest map[string]any) ([]byte, error) {
	f.store(manifest)
	return nil, nil
}

func (f *fakeKube) store(manifest map[string]any) {
	f.version++
	meta, _ := manifest["metadata"].(map[string]any)
	meta["resourceVersion"] = string(rune('0' + f.version))
	f.obj = manifest
}

type errConflict struct{}

func (errConflict) Error() string { return "conflict" }

func TestFirstReplicaTakesTheLease(t *testing.T) {
	kube := &fakeKube{}
	e := New(kube, "head", "head-0")
	held, err := e.tryAcquire(context.Background())
	if err != nil || !held {
		t.Fatalf("свободная лиза не взята: held=%v err=%v", held, err)
	}
}

func TestStandbyWaitsWhileTheLeaseIsFresh(t *testing.T) {
	kube := &fakeKube{}
	first := New(kube, "head", "head-0")
	if held, _ := first.tryAcquire(context.Background()); !held {
		t.Fatal("первая реплика не взяла лизу")
	}
	second := New(kube, "head", "head-1")
	if held, _ := second.tryAcquire(context.Background()); held {
		t.Fatal("вторая реплика встала лидером при живой лизе")
	}
}

func TestStandbyTakesOverWhenTheHolderStops(t *testing.T) {
	kube := &fakeKube{}
	first := New(kube, "head", "head-0")
	first.now = func() time.Time { return time.Now().Add(-time.Hour) }
	if held, _ := first.tryAcquire(context.Background()); !held {
		t.Fatal("первая реплика не взяла лизу")
	}
	second := New(kube, "head", "head-1")
	if held, _ := second.tryAcquire(context.Background()); !held {
		t.Fatal("протухшая лиза не подобрана")
	}
}

// Отказ записи означает, что кто-то успел раньше: лидером становиться нельзя
func TestLostRaceDoesNotMakeALeader(t *testing.T) {
	kube := &fakeKube{putFails: true}
	first := New(kube, "head", "head-0")
	if held, _ := first.tryAcquire(context.Background()); !held {
		t.Fatal("создание лизы должно было пройти")
	}
	second := New(kube, "head", "head-1")
	second.now = func() time.Time { return time.Now().Add(time.Hour) }
	if held, _ := second.tryAcquire(context.Background()); held {
		t.Fatal("проигранная гонка сделала второго лидером")
	}
}
