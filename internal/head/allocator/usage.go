package allocator

import (
	"sort"

	"wingsnet.org/federation/internal/head/profiles"
)

// RowUsage - трафик одной строки списка: сервер плюс транспорт. Ровно та
// нарезка, которую человек видит в приложении
type RowUsage struct {
	Name      string
	Transport string
	UpBytes   uint64
	DownBytes uint64
	LastSeen  int64
}

// Usage - что человек пронёс, разложенное по строкам его списка.
//
// Имя берётся от ноды, как и в ссылках: на всех устройствах список обязан
// выглядеть одинаково, иначе один и тот же сервер зовётся по-разному
func (a *Allocator) UsageRows(userID string) []RowUsage {
	a.mu.Lock()
	defer a.mu.Unlock()
	alloc, ok := a.state[userID]
	if !ok {
		return nil
	}
	numbers := a.countryNumbers()
	out := make([]RowUsage, 0, len(alloc.Profiles)*2)
	for _, p := range alloc.Profiles {
		node, err := a.reg.Get(p.NodeID)
		if err != nil {
			continue
		}
		name := profiles.DisplayName(node.Passport.GetCountry(), numbers[p.NodeID], "")
		for transport, used := range p.Usage {
			if used.UpBytes == 0 && used.DownBytes == 0 {
				continue
			}
			row := RowUsage{
				Name: name, Transport: transport,
				UpBytes: used.UpBytes, DownBytes: used.DownBytes,
			}
			if !used.LastSeen.IsZero() {
				row.LastSeen = used.LastSeen.Unix()
			}
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Transport < out[j].Transport
	})
	return out
}
