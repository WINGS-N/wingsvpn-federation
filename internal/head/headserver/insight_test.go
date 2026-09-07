package headserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/head/aggregator"
	"wingsnet.org/federation/internal/head/oracle"
	"wingsnet.org/federation/internal/head/registry"
	"wingsnet.org/federation/internal/head/tokens"
)

// Спокойный пользователь тоже виден в сводке: сигналов на нём нет, но доступ
// выдан, и в счётчике полос он обязан быть
func TestOracleOverviewCountsEveryoneWithAccess(t *testing.T) {
	srv := New(registry.New(), aggregator.New(), tokens.New(), "fleet-secret")
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	srv.SetOracle(judge)
	srv.SetAllocator(&fakeAllocations{users: []string{"quiet-1", "quiet-2"}}, "https://example.org")

	got, err := srv.OracleOverview(context.Background(), &headpb.OracleOverviewRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSubjectsTotal() != 2 {
		t.Fatalf("субъектов = %d, а доступ выдан двоим", got.GetSubjectsTotal())
	}
	if got.GetFull() != 2 {
		t.Fatalf("полный доступ = %d, а спокойных двое", got.GetFull())
	}
	if got.GetWatched() != 0 {
		t.Fatalf("обвиняемых = %d, а сигналов не было ни одного", got.GetWatched())
	}
}

// pagedDomains изображает историю, из которой панель тянет страницами
type pagedDomains struct {
	rows []DomainStat
}

func (p pagedDomains) TopDomainsPage(_ string, _ time.Time, limit, offset int) ([]DomainStat, int64, error) {
	total := int64(len(p.rows))
	if offset >= len(p.rows) {
		return nil, total, nil
	}
	end := offset + limit
	if end > len(p.rows) {
		end = len(p.rows)
	}
	return p.rows[offset:end], total, nil
}

// Хвост в тысячу доменов на экран не лезет, поэтому карточка обязана резаться на
// страницы и говорить, сколько их всего
func TestOracleSubjectPagesDomainsAndSignals(t *testing.T) {
	srv := New(registry.New(), aggregator.New(), tokens.New(), "fleet-secret")
	judge := oracle.NewJudge(oracle.NewRulesScorer())
	srv.SetOracle(judge)

	now := time.Now()
	for i := 0; i < 7; i++ {
		judge.Observe(oracle.Signal{
			ClientID: "user-9",
			Kind:     fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT,
			Count:    uint32(i + 1),
			Observed: now.Add(-time.Duration(i) * time.Minute),
			NodeID:   "node-1",
		})
	}
	rows := make([]DomainStat, 0, 12)
	for i := 0; i < 12; i++ {
		rows = append(rows, DomainStat{Domain: fmt.Sprintf("d%02d.example", i), Hits: int64(100 - i)})
	}
	srv.SetDomainHistory(pagedDomains{rows: rows})

	got, err := srv.OracleSubject(context.Background(), &headpb.OracleSubjectRequest{
		SubjectId:   "user-9",
		DomainLimit: 5, DomainOffset: 10,
		SignalLimit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetDomainsTotal() != 12 {
		t.Fatalf("доменов всего = %d, а их дюжина", got.GetDomainsTotal())
	}
	if len(got.GetDomains()) != 2 {
		t.Fatalf("на последней странице %d доменов, а осталось два", len(got.GetDomains()))
	}
	if got.GetSignalsTotal() != 7 {
		t.Fatalf("сигналов всего = %d, а записали семь", got.GetSignalsTotal())
	}
	if len(got.GetSignals()) != 3 {
		t.Fatalf("на странице %d сигналов, а просили три", len(got.GetSignals()))
	}
}
