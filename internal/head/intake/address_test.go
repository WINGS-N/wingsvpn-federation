package intake

import (
	"testing"
)

type fakeSeen map[string][]string

func (f fakeSeen) Matches(subjectID, claimed string) (bool, bool) {
	addrs, ok := f[subjectID]
	if !ok || len(addrs) == 0 {
		return false, false
	}
	for _, addr := range addrs {
		if addr == claimed {
			return true, true
		}
	}
	return false, true
}

func serverWithSeen(seen fakeSeen) (*Server, *[]string) {
	var claims []string
	srv := New(memKeys{}, newSink())
	srv.SetSeen(seen)
	srv.SetAddressSink(func(subjectID, claimed string) {
		claims = append(claims, subjectID+" "+claimed)
	})
	return srv, &claims
}

func TestMatchingAddressIsSilent(t *testing.T) {
	srv, claims := serverWithSeen(fakeSeen{"user-1": {"203.0.113.7"}})
	srv.checkAddress("user-1", "203.0.113.7")
	if len(*claims) != 0 {
		t.Fatalf("обвинили при совпадении адреса: %+v", *claims)
	}
}

func TestAMismatchIsReported(t *testing.T) {
	srv, claims := serverWithSeen(fakeSeen{"user-1": {"203.0.113.7"}})
	srv.checkAddress("user-1", "198.51.100.9")
	if len(*claims) != 1 {
		t.Fatalf("расхождение адресов пропустили: %+v", *claims)
	}
}

// Нода ещё ничего не видела - сверять не с чем, и обвинять не за что
func TestNothingSeenMeansNothingToJudge(t *testing.T) {
	srv, claims := serverWithSeen(fakeSeen{})
	srv.checkAddress("user-1", "198.51.100.9")
	if len(*claims) != 0 {
		t.Fatalf("обвинили, ничего не увидев: %+v", *claims)
	}
}

// Клиент промолчал или прислал мусор: это не обвинение
func TestGarbageIsIgnored(t *testing.T) {
	srv, claims := serverWithSeen(fakeSeen{"user-1": {"203.0.113.7"}})
	srv.checkAddress("user-1", "")
	srv.checkAddress("user-1", "не адрес")
	if len(*claims) != 0 {
		t.Fatalf("мусор в поле приняли за расхождение: %+v", *claims)
	}
}

// У человека несколько живых соединений, совпасть должно с любым
func TestAnyOfTheSeenAddressesCounts(t *testing.T) {
	srv, claims := serverWithSeen(fakeSeen{"user-1": {"198.51.100.1", "203.0.113.7"}})
	srv.checkAddress("user-1", "203.0.113.7")
	if len(*claims) != 0 {
		t.Fatalf("не засчитали совпадение со вторым адресом: %+v", *claims)
	}
}
