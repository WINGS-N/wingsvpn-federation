package allocator

import "wingsnet.org/federation/internal/head/upstream"

// Купленные подписки идут в тот же список серверов, что и свои ноды: для
// человека это один список, а не два сорта доступа. Разница только в учёте -
// за чужой сервер донорам не начисляется нихуя, он куплен, а не отдан

// Upstreams отдаёт ссылки купленных серверов, закреплённые за человеком
type Upstreams interface {
	For(subjectID string) []upstream.Link
}

// SetUpstreams включает раздачу купленного
func (a *Allocator) SetUpstreams(up Upstreams) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upstreams = up
}

// upstreamLinks - что человеку причитается с купленных подписок
func (a *Allocator) upstreamLinks(userID string) []string {
	a.mu.Lock()
	up := a.upstreams
	a.mu.Unlock()
	if up == nil {
		return nil
	}
	links := up.For(userID)
	out := make([]string, 0, len(links))
	for _, link := range links {
		out = append(out, link.Raw)
	}
	return out
}
