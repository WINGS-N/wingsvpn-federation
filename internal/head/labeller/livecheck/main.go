package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"wingsnet.org/federation/internal/head/labeller"
)

// Живая проверка второго захода: те же цифры, что и в первом круге, но с
// доменами. Смотрим, снимет ли модель ложное обвинение
func main() {
	client := labeller.NewClient(os.Getenv("ANTHROPIC_API_KEY"), "")
	loop := labeller.NewLoop(client, store{}, "features-v2", func(f string, a ...any) {
		fmt.Printf(f+"\n", a...)
	})
	loop.SetDomains(domains{}, 7*24*time.Hour)
	loop.Once(context.Background())
}

// store отдаёт два снимка, оба выглядят подозрительно по числам
type store struct{}

func (store) Unlabelled(string, int) ([]labeller.Snapshot, error) {
	return []labeller.Snapshot{
		{ID: 1, SubjectID: "torrent", Values: map[string]float64{
			"requests": 5200, "domains": 14, "bytes_per_request": 260000, "up_ratio": 0.58,
			"long_lived_share": 0.62, "no_domain_share": 0.81, "distinct_bare_peers": 260,
			"peer_port_hits": 3900, "ports_touched": 6, "active_hours": 17,
		}},
		{ID: 2, SubjectID: "checker", Values: map[string]float64{
			"requests": 9800, "domains": 940, "domains_per_hour": 470, "bytes_per_request": 620,
			"long_lived_share": 0, "random_name_share": 0.41, "active_hours": 24,
			"fresh_domains": 22, "fresh_domain_share": 0.63,
		}},
	}, nil
}

func (store) SetLabel(ids []uint64, label int16, _ string) error {
	for _, id := range ids {
		fmt.Printf("result: id=%d label=%d\n", id, label)
	}
	return nil
}

func (store) SetLabelWhy(reasons map[uint64]string, label int16, _ string) error {
	for id, why := range reasons {
		fmt.Printf("result: id=%d label=%d why=%s\n", id, label, why)
	}
	return nil
}

// domains отдаёт разные походы: у первого торренты, у второго кардинг
type domains struct{}

func (domains) TopDomains(subjectID string, _ time.Time, _ int) ([]labeller.Domain, error) {
	if subjectID == "torrent" {
		return []labeller.Domain{
			{Name: "rutracker.org", Hits: 42, Bytes: 3 << 20},
			{Name: "nnmclub.to", Hits: 18, Bytes: 1 << 20},
			{Name: "youtube.com", Hits: 260, Bytes: 4 << 30},
			{Name: "vk.com", Hits: 90, Bytes: 200 << 20},
		}, nil
	}
	return []labeller.Domain{
		{Name: "cc-checker-live.su", Hits: 480, Bytes: 2 << 20},
		{Name: "dumpsshop24.cc", Hits: 210, Bytes: 1 << 20},
		{Name: "x7f2k9qm1z.top", Hits: 900, Bytes: 3 << 20},
		{Name: "combolist-fresh.ru", Hits: 130, Bytes: 900 << 10},
	}, nil
}
