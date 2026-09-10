package intake

import (
	"log"

	fedpb "wingsnet.org/federation/gen/fedpb"
)

// AcceptCarried принимает расписки, которые принесла нода за клиента.
//
// Имя человека берётся из самой расписки, а не снаружи: панель тут не
// участвовала, и подтверждает авторство подпись. Проверки те же самые, поэтому
// курьер ничего не выигрывает от того, что нёс чужое
func (s *Server) AcceptCarried(receipts []*fedpb.TrafficReceipt) (accepted, rejected int) {
	now := s.now()
	for _, r := range receipts {
		subject := r.GetClientId()
		if subject == "" {
			rejected++
			continue
		}
		key, ok, err := s.keys.Get(subject)
		if err != nil || !ok {
			rejected++
			continue
		}
		if err := s.check(subject, key, r, now); err != nil {
			rejected++
			continue
		}
		if err := s.sink.Accept(subject, r); err != nil {
			// Повтор по nonce это норма: клиент шлёт одно и то же всеми путями
			// сразу, лишь бы доехало хоть чем-то
			rejected++
			continue
		}
		accepted++
	}
	if rejected > 0 {
		log.Printf("intake: %d carried receipts accepted, %d refused", accepted, rejected)
	}
	return accepted, rejected
}
