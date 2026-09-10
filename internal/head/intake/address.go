package intake

import (
	"net"
	"strings"
)

// Seen отвечает, видела ли нода этот адрес у участника.
//
// Именно ответ, а не список: наверх едут отпечатки, а не адреса, и вытаскивать
// их обратно незачем
type Seen interface {
	Matches(subjectID, claimed string) (match bool, known bool)
}

// SetSeen включает сверку заявленного адреса с тем, что видно ноде
func (s *Server) SetSeen(seen Seen) { s.seen = seen }

// SetAddressSink говорит, куда слать расхождение
func (s *Server) SetAddressSink(fn func(subjectID, claimed string)) {
	s.addressSink = fn
}

// checkAddress сверяет то, что клиент сказал о себе, с тем, что видит нода.
//
// Сам себя он этим сдаёт, и в том и смысл: расхождение означает, что поверх
// нашего туннеля крутится ещё один или профилем пользуется не он. Совпадение
// при этом ничего не доказывает, соврать в поле может кто угодно, поэтому
// сигнал только на расхождение
func (s *Server) checkAddress(subjectID, claimed string) {
	claimed = strings.TrimSpace(claimed)
	if claimed == "" || s.seen == nil || s.addressSink == nil {
		return
	}
	if net.ParseIP(claimed) == nil {
		return
	}
	match, known := s.seen.Matches(subjectID, claimed)
	if !known {
		// Нода ещё ничего не видела: сверять не с чем, и обвинять не за что
		return
	}
	if match {
		return
	}
	s.addressSink(subjectID, claimed)
}
