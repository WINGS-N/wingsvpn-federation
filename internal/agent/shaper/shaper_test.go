package shaper

import (
	"context"
	"strings"
	"testing"
)

func recorder() (*Shaper, *[]string) {
	var calls []string
	s := New("wg0")
	s.SetRunner(func(_ context.Context, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	})
	return s, &calls
}

// Потолок ставится на адрес пира, а корень дерева заводится один раз
func TestApplyShapesThePeerAddress(t *testing.T) {
	s, calls := recorder()
	ctx := context.Background()
	if err := s.Apply(ctx, "10.8.0.5/32", Limit{DownBps: 2 << 20}); err != nil {
		t.Fatalf("шейпер обосрался: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "qdisc replace dev wg0") {
		t.Fatalf("корень не завели: %v", *calls)
	}
	if !strings.Contains(joined, "match ip dst 10.8.0.5/32") {
		t.Fatalf("фильтр не на адрес пира: %v", *calls)
	}
	// 2 MB/s это 16777216 бит
	if !strings.Contains(joined, "rate 16777216bit") {
		t.Fatalf("полоса посчитана неверно: %v", *calls)
	}
}

// Тот же потолок второй раз ядро дёргать не должен: круг идёт часто, а правило
// не меняется
func TestApplyIsQuietWhenNothingChanged(t *testing.T) {
	s, calls := recorder()
	ctx := context.Background()
	_ = s.Apply(ctx, "10.8.0.5/32", Limit{DownBps: 1 << 20})
	before := len(*calls)
	_ = s.Apply(ctx, "10.8.0.5/32", Limit{DownBps: 1 << 20})
	if len(*calls) != before {
		t.Fatalf("дёрнули ядро зря: %v", (*calls)[before:])
	}
}

// Снятый потолок означает полосу без ограничения, а не нулевую: ноль в htb
// означал бы, что человек не качает вообще ничего
func TestZeroLimitMeansUnlimited(t *testing.T) {
	s, calls := recorder()
	_ = s.Apply(context.Background(), "10.8.0.7/32", Limit{})
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "rate "+unlimitedRate) {
		t.Fatalf("без потолка выставили не ту полосу: %v", *calls)
	}
}

// Мусор вместо адреса не должен уезжать в ядро
func TestGarbageAddressIsRefused(t *testing.T) {
	s, calls := recorder()
	if err := s.Apply(context.Background(), "не адрес", Limit{}); err == nil {
		t.Fatal("мусорный адрес приняли")
	}
	if len(*calls) != 0 {
		t.Fatalf("с мусором полезли в ядро: %v", *calls)
	}
}
