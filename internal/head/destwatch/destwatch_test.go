package destwatch

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"wingsnet.org/federation/internal/head/fleet"
	"wingsnet.org/federation/internal/scan"
)

type memFleet struct {
	cur     fleet.Settings
	updates int
}

func (m *memFleet) Settings() fleet.Settings { return m.cur }
func (m *memFleet) Update(next fleet.Settings) (fleet.Settings, error) {
	next.ConfigVersion = m.cur.ConfigVersion + 1
	m.cur = next
	m.updates++
	return next, nil
}

func fixed() *rand.Rand { return rand.New(rand.NewSource(1)) }

// Рабочий dest не трогаем: смена перезапускает Xray на всём флоте и рвёт живые
// соединения, поэтому повод должен быть настоящий.
func TestAWorkingDestIsLeftAlone(t *testing.T) {
	f := &memFleet{cur: fleet.Settings{AutoDest: true, RealityDest: "good.example:443"}}
	w := New(Options{Fleet: f, Rand: fixed(), Probe: func(context.Context) ([]*scan.Result, error) {
		return []*scan.Result{
			{Target: "good.example:443", Feasible: true},
			{Target: "other.example:443", Feasible: true},
		}, nil
	}})
	w.checkOnce(t.Context())
	if f.cur.RealityDest != "good.example:443" {
		t.Errorf("dest сменили без причины: %q", f.cur.RealityDest)
	}
	if len(f.cur.DestPool) != 2 {
		t.Errorf("пул не обновился: %v", f.cur.DestPool)
	}
}

// Пул из проверенных целей нужен, чтобы ноды разъехались по разным dest: общий
// на всех означает, что одно правило у цензора роняет флот целиком.
//
// Проверяется распределение на выборке, а не на горстке имён: на пяти-шести
// значениях перекос - обычное дело для любого хеша, и тест на них ловил бы
// удачу, а не свойство.
func TestNodesSpreadAcrossThePool(t *testing.T) {
	set := fleet.Settings{DestPool: []string{"a:443", "b:443", "c:443"}}
	counts := map[string]int{}
	const nodes = 300
	for i := 0; i < nodes; i++ {
		counts[set.DestFor(fmt.Sprintf("%032x", i))]++
	}
	if len(counts) != len(set.DestPool) {
		t.Fatalf("задействовано %d dest из %d: %v", len(counts), len(set.DestPool), counts)
	}
	// Совсем ровного деления никто не обещает, но пул, где на цель приходится
	// меньше десятой доли флота, свою задачу не выполняет
	for dest, n := range counts {
		if n < nodes/10 {
			t.Errorf("на %s пришлось всего %d нод из %d", dest, n, nodes)
		}
	}
}

// Нода должна держаться своего dest: он уходит в выданные ссылки как SNI, и
// смена ломает каждую из них.
func TestANodeKeepsItsDest(t *testing.T) {
	set := fleet.Settings{DestPool: []string{"a:443", "b:443", "c:443"}}
	const id = "ffe6738a4961700d6ea197d58f6d91e9"
	first := set.DestFor(id)
	for i := 0; i < 10; i++ {
		if got := set.DestFor(id); got != first {
			t.Fatalf("dest ноды скачет: %q и %q", first, got)
		}
	}
}

// Пустой пул - это старое поведение, и оно должно продолжать работать.
func TestWithoutAPoolEverybodyGetsTheOneDest(t *testing.T) {
	set := fleet.Settings{RealityDest: "only.example:443"}
	if got := set.DestFor("n1"); got != "only.example:443" {
		t.Errorf("DestFor = %q без пула", got)
	}
}

// Пропавший dest - повод переехать: иначе флот держит инбаунды, которые падают
// на хендшейке, продолжая рапортовать о здоровье.
func TestADeadDestIsReplaced(t *testing.T) {
	f := &memFleet{cur: fleet.Settings{AutoDest: true, RealityDest: "dead.example:443"}}
	w := New(Options{Fleet: f, Rand: fixed(), Probe: func(context.Context) ([]*scan.Result, error) {
		return []*scan.Result{
			{Target: "dead.example:443", Feasible: false},
			{Target: "alive.example:443", Feasible: true},
		}, nil
	}})
	w.checkOnce(t.Context())
	if f.cur.RealityDest != "alive.example:443" {
		t.Errorf("dest = %q, want alive.example:443", f.cur.RealityDest)
	}
}

// Неудачная проверка - не повод дёргать флот: сеть башки могла моргнуть, а
// цена ошибки тут перезапуск Xray у всех.
func TestAFailedProbeKeepsTheCurrentDest(t *testing.T) {
	f := &memFleet{cur: fleet.Settings{AutoDest: true, RealityDest: "good.example:443"}}
	w := New(Options{Fleet: f, Rand: fixed(), Probe: func(context.Context) ([]*scan.Result, error) {
		return nil, errors.New("network down")
	}})
	w.checkOnce(t.Context())
	if f.cur.RealityDest != "good.example:443" || f.updates != 0 {
		t.Errorf("dest сменили после неудачной проверки: %q", f.cur.RealityDest)
	}
}

// Пустой пул тоже не повод: остаться на прежнем лучше, чем остаться без dest.
func TestAnEmptyPoolKeepsTheCurrentDest(t *testing.T) {
	f := &memFleet{cur: fleet.Settings{AutoDest: true, RealityDest: "good.example:443"}}
	w := New(Options{Fleet: f, Rand: fixed(), Probe: func(context.Context) ([]*scan.Result, error) {
		return []*scan.Result{{Target: "x:443", Feasible: false}}, nil
	}})
	w.checkOnce(t.Context())
	if f.updates != 0 {
		t.Errorf("dest сменили при пустом пуле: %q", f.cur.RealityDest)
	}
}

// Выключенный автовыбор означает, что dest выбран человеком - лезть туда нельзя.
func TestAPinnedDestIsNeverTouched(t *testing.T) {
	f := &memFleet{cur: fleet.Settings{AutoDest: false, RealityDest: "pinned.example:443"}}
	called := false
	w := New(Options{Fleet: f, Rand: fixed(), Probe: func(context.Context) ([]*scan.Result, error) {
		called = true
		return nil, nil
	}})
	w.checkOnce(t.Context())
	if called || f.updates != 0 {
		t.Error("автовыбор полез в dest, закреплённый вручную")
	}
}

// Скан идёт минутами. Всё, что оператор поменял за это время, должно уцелеть:
// запись снимка, взятого до скана, откатывает его правки - так уже потерялся
// включённый ML-DSA-65.
func TestChangesMadeDuringTheProbeSurvive(t *testing.T) {
	f := &memFleet{cur: fleet.Settings{AutoDest: true, RealityDest: "dead.example:443"}}
	w := New(Options{Fleet: f, Rand: fixed(), Probe: func(context.Context) ([]*scan.Result, error) {
		// Оператор нажал "сохранить" ровно посреди проверки
		f.cur.PostQuantum = true
		f.cur.XrayVersion = "v26.7.11-wv"
		return []*scan.Result{{Target: "alive.example:443", Feasible: true}}, nil
	}})
	w.checkOnce(t.Context())

	if !f.cur.PostQuantum {
		t.Error("включённый ML-DSA-65 откатился обратно")
	}
	if f.cur.XrayVersion != "v26.7.11-wv" {
		t.Errorf("версия сборки откатилась: %q", f.cur.XrayVersion)
	}
	if f.cur.RealityDest != "alive.example:443" {
		t.Errorf("dest не переехал: %q", f.cur.RealityDest)
	}
}
