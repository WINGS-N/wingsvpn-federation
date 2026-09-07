package domainwatch

import (
	"time"

	xraypb "wingsnet.org/federation/gen/xraypb"
)

// Наблюдения VK TURN приходят не от ядра, а с wg-интерфейса, потому что у релея
// нет ни sniffing, ни access-лога нихуя. Форма у них беднее: есть имя и
// отпечаток, а объёма и длительности нет, видно только начало соединения

// ObserveRelay складывает наблюдение, снятое с wg-интерфейса
func (w *Watcher) ObserveRelay(profileID, domain, ja3, ja4 string, at time.Time) {
	if profileID == "" {
		return
	}
	// Гоним общим путём, событие ядра и наблюдение с интерфейса различаются
	// полнотой, а не смыслом, и плодить вторую ветку незачем нахуй
	w.observeFor(profileID, &xraypb.AccessEvent{
		Email:        profileID,
		TargetDomain: domain,
		TargetPort:   443,
		Network:      "tcp",
		AtUnixNano:   at.UnixNano(),
		TlsJa3:       ja3,
		TlsJa4:       ja4,
	})
}
