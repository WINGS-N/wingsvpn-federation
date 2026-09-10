package registry

import (
	"net"
	"strings"
)

// NodeByAddress ищет ноду по адресу, который назвал клиент.
//
// Клиент внутренних идентификаторов не знает и знать не должен: он подписывает
// расписку тем, что видит в ссылке. Без этого перевода сверка не сойдётся ни по
// одному ключу, и честные ноды выглядели бы как ноды без единой расписки.
//
// В ссылке адрес всегда с портом, а паспорт несёт голый ip, поэтому порт тут
// отрезается. Сверка строка-в-строку отбивала каждую расписку как названную на
// чужую ноду, и потеря выглядела так, будто клиенты ничего не подписывают
func (r *Registry) NodeByAddress(address string) (string, bool) {
	host := hostOf(address)
	if host == "" {
		return "", false
	}
	for _, node := range r.List() {
		// Адрес релея нода сообщает сама, и по нему клиент её и набирает
		if node.RelayEndpoint != "" && hostOf(node.RelayEndpoint) == host {
			return node.ID, true
		}
		if node.Passport == nil {
			continue
		}
		for _, own := range node.Passport.GetAddresses() {
			if hostOf(own.GetAddress()) == host {
				return node.ID, true
			}
		}
	}
	return "", false
}

// hostOf приводит адрес к голому хосту: с портом, без порта и в скобках IPv6 -
// это всё одна и та же машина
func hostOf(address string) string {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(trimmed, "[]")
}
