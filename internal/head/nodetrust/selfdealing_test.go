package nodetrust

import (
	"testing"
	"time"
)

const gib = uint64(1) << 30

type fakeMix map[string]map[string]uint64

func (f fakeMix) SignedByNodeAndSubject(time.Time, time.Time) (map[string]map[string]uint64, error) {
	return map[string]map[string]uint64(f), nil
}

type noResolve struct{}

func (noResolve) NodeByAddress(address string) (string, bool) { return address, true }

func auditorFor(judge *Judge) *Auditor {
	return NewAuditor(nil, nil, noResolve{}, judge, nil)
}

// Нода, у которой весь объём висит на паре клиентов, обслуживает скорее всего
// своего же хозяина
func TestConcentratedNodeIsAccused(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	auditor.JudgeSelfDealing(fakeMix{
		"n1": {"user-1": 200 * gib, "user-2": 100 * gib, "user-3": 2 * gib},
	})
	verdict := judge.Judge("n1")
	if verdict.Reasons[ReasonSelfDealing] == 0 {
		t.Fatal("нода с двумя клиентами на весь трафик не получила ни одного обвинения")
	}
	if verdict.Trust >= StartingTrust {
		t.Fatalf("доверие %d, а обвинение было", verdict.Trust)
	}
}

// Нода с размазанным трафиком чиста, сколько бы через неё ни прошло
func TestSpreadTrafficIsNotSelfDealing(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	mix := map[string]uint64{}
	for i := 0; i < 20; i++ {
		mix[string(rune('a'+i))] = 50 * gib
	}
	auditor.JudgeSelfDealing(fakeMix{"n1": mix})
	if judge.Judge("n1").Trust != StartingTrust {
		t.Fatal("нода с двумя десятками клиентов обвинена в самообслуживании")
	}
}

// На пустой ноде один живой человек законно даёт все сто процентов, и вешать
// на неё обвинение значит выебать невиновного
func TestSmallVolumeIsNotJudged(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	auditor.JudgeSelfDealing(fakeMix{"n1": {"user-1": 3 * gib}})
	if judge.Judge("n1").Trust != StartingTrust {
		t.Fatal("нода с тремя гигабайтами обвинена в самообслуживании")
	}
}

// Чем сильнее перекос, тем дороже обвинение
func TestWorseConcentrationCostsMore(t *testing.T) {
	total := func(mix map[string]uint64) int {
		judge := NewJudge()
		auditorFor(judge).JudgeSelfDealing(fakeMix{"n1": mix})
		return judge.Judge("n1").Trust
	}
	// Всё на одном против почти порогового перекоса
	alone := total(map[string]uint64{"user-1": 300 * gib})
	borderline := total(map[string]uint64{
		"user-1": 150 * gib, "user-2": 130 * gib, "user-3": 30 * gib,
	})
	if alone >= borderline {
		t.Fatalf("полный перекос (%d) оценён не хуже пограничного (%d)", alone, borderline)
	}
}

type fakeDonors map[string]string

func (f fakeDonors) DonorOfNode(nodeID string) (string, bool) {
	donor, ok := f[nodeID]
	return donor, ok
}

func treeOf(m map[string][]string) *Tree {
	tree := NewTree()
	tree.Replace(m)
	return tree
}

// Дерево ловит то, что концентрация проглядит: клиентов дохуя, но все они
// приглашены самим донором
func TestOwnInviteesAreCaughtEvenWhenSpread(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	mix := map[string]uint64{}
	ancestors := map[string][]string{}
	for i := 0; i < 12; i++ {
		id := "user-" + string(rune('a'+i))
		mix[id] = 30 * gib
		ancestors[id] = []string{"admin-7"}
	}
	auditor.WatchInviteTree(treeOf(ancestors), fakeDonors{"n1": "admin-7"})
	auditor.JudgeSelfDealing(fakeMix{"n1": mix})

	if judge.Judge("n1").Reasons[ReasonSelfDealing] == 0 {
		t.Fatal("нода, возящая трафик своим же приглашённым, не обвинена")
	}
}

// Чужие люди на ноде - обычная работа, за это карать нельзя
func TestStrangersOnANodeAreFine(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	auditor.WatchInviteTree(treeOf(map[string][]string{
		"user-1": {"admin-1"}, "user-2": {"admin-2"}, "user-3": {"admin-3"},
	}), fakeDonors{"n1": "admin-7"})
	auditor.JudgeSelfDealing(fakeMix{"n1": {
		"user-1": 100 * gib, "user-2": 90 * gib, "user-3": 80 * gib,
	}})
	if judge.Judge("n1").Trust != StartingTrust {
		t.Fatal("нода с чужими клиентами обвинена в самообслуживании")
	}
}

// Ферма на два колена: донор позвал приглашающего, тот завёл юзеров. Цепочка
// целиком для того и передаётся
func TestSecondGenerationFarmIsCaught(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	auditor.WatchInviteTree(treeOf(map[string][]string{
		"user-1": {"admin-9", "admin-7"},
		"user-2": {"admin-9", "admin-7"},
	}), fakeDonors{"n1": "admin-7"})
	auditor.JudgeSelfDealing(fakeMix{"n1": {"user-1": 200 * gib, "user-2": 100 * gib}})
	if judge.Judge("n1").Reasons[ReasonSelfDealing] == 0 {
		t.Fatal("ферма на два колена прошла мимо суда")
	}
}

// Пока карты нет, судим по концентрации: пустое дерево и неприсланное это разные
// вещи, и путать их нельзя
func TestWithoutTheTreeConcentrationStillWorks(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	auditor.WatchInviteTree(NewTree(), fakeDonors{"n1": "admin-7"})
	auditor.JudgeSelfDealing(fakeMix{"n1": {"user-1": 300 * gib}})
	if judge.Judge("n1").Reasons[ReasonSelfDealing] == 0 {
		t.Fatal("без карты приглашений грубая проверка не сработала")
	}
}

// Донор, который сам качает через свою ноду, это тот же случай
func TestDonorPullingThroughOwnNodeIsCaught(t *testing.T) {
	judge := NewJudge()
	auditor := auditorFor(judge)
	auditor.WatchInviteTree(treeOf(map[string][]string{"user-5": {"admin-1"}}),
		fakeDonors{"n1": "admin-7"})
	auditor.JudgeSelfDealing(fakeMix{"n1": {
		"admin-7": 250 * gib, "user-5": 20 * gib,
	}})
	if judge.Judge("n1").Reasons[ReasonSelfDealing] == 0 {
		t.Fatal("донор, качающий через свою же ноду, не обвинён")
	}
}
