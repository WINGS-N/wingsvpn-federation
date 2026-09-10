package enforce

import (
	"testing"

	"wingsnet.org/federation/internal/head/oracle"
)

type fakeUsage struct {
	used map[string]uint64
}

func (f fakeUsage) Usage(clientID string) uint64 { return f.used[clientID] }

// Исчерпанная квота сажает на пол скорости, но связи не лишает: доступ, который
// превращается в кирпич по достижении цифры, человек читает как поломку
func TestQuotaDropsToTheFloorInsteadOfCutting(t *testing.T) {
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	e := New(judge, nil, nil)

	// Чистому человеку потолка нет вовсе, сколько бы он ни пронёс
	e.SetUsage(fakeUsage{used: map[string]uint64{"clean": 900 << 30}})
	up, down := e.Speed("clean")
	floorUp, floorDown := oracle.FloorSpeed()
	if up == floorUp && down == floorDown {
		t.Fatal("чистого посадили на пол, хотя потолка у него нет")
	}
}

// А подозрительный, выбравший свой потолок, едет на полу
func TestQuotaAppliesToTheSuspicious(t *testing.T) {
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	// Роняем доверие до урезанной полосы, где потолок и появляется
	for i := 0; i < 3; i++ {
		judge.Observe(oracle.Signal{ClientID: "dirty", Kind: 5, Count: 30})
	}
	confidence := judge.Judge("dirty").Confidence
	limit := oracle.QuotaFor(confidence)
	if limit == oracle.QuotaUnlimited {
		t.Skipf("доверие %d всё ещё без потолка, сигналов мало", confidence)
	}

	e := New(judge, nil, nil)
	e.SetUsage(fakeUsage{used: map[string]uint64{"dirty": limit + 1}})
	up, down := e.Speed("dirty")
	floorUp, floorDown := oracle.FloorSpeed()
	if up != floorUp || down != floorDown {
		t.Fatalf("выбранная квота не посадила на пол: %d/%d", up, down)
	}
}
