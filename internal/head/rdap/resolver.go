package rdap

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Store хранит уже узнанное. Домен стареет медленно, и спрашивать реестр про
// одно имя дважды - значит бесплатно дарить ему наш профиль запросов
type Store interface {
	// Age отдаёт дату регистрации и когда мы её узнали
	Age(domain string) (registered time.Time, checked time.Time, known bool)
	Put(domain string, registered time.Time, checked time.Time) error
	// PutMiss запоминает, что ответа нет: у половины национальных зон RDAP
	// отсутствует как явление, и долбиться туда каждый круг незачем
	PutMiss(domain string, checked time.Time) error
}

// missTTL - как долго помним отказ. Реестр мог просто лежать, а зона могла за
// это время и завести себе RDAP
const missTTL = 7 * 24 * time.Hour

// perRound - сколько новых имён разрешаем спросить за круг разбора. Реестры
// режут по частоте, и вывалить им сотню имён разом это верный способ словить
// бан на весь флот
const perRound = 20

// Resolver отдаёт возраст домена, спрашивая реестр только о том, чего ещё не
// знает
type Resolver struct {
	client *Client
	store  Store
	now    func() time.Time
	log    func(string, ...any)

	mu sync.Mutex
	// spent - сколько запросов потратили в текущем круге
	spent int
}

func NewResolver(client *Client, store Store, log func(string, ...any)) *Resolver {
	return &Resolver{client: client, store: store, now: time.Now, log: log}
}

// SetNow подменяет часы. Только для тестов
func (r *Resolver) SetNow(now func() time.Time) { r.now = now }

// StartRound обнуляет счётчик запросов. Зовётся разбором перед проходом по
// субъектам
func (r *Resolver) StartRound() {
	r.mu.Lock()
	r.spent = 0
	r.mu.Unlock()
}

// AgeDays - сколько дней домену. Второе значение false означает "хуй знает", а
// НЕ "домен свежий": судить по незнанию нельзя ни в коем случае, иначе первым в
// карантин уедет любой, чья зона RDAP не держит
func (r *Resolver) AgeDays(ctx context.Context, domain string) (float64, bool) {
	name := normalize(domain)
	if name == "" {
		return 0, false
	}
	now := r.now()
	if r.store != nil {
		registered, checked, known := r.store.Age(name)
		if known {
			if registered.IsZero() {
				// Отказ помним ограниченное время
				if now.Sub(checked) < missTTL {
					return 0, false
				}
			} else {
				return now.Sub(registered).Hours() / 24, true
			}
		}
	}

	r.mu.Lock()
	if r.spent >= perRound {
		r.mu.Unlock()
		return 0, false
	}
	r.spent++
	r.mu.Unlock()

	registered, err := r.client.Registered(ctx, name)
	if err != nil {
		if r.store != nil {
			_ = r.store.PutMiss(name, now)
		}
		// Зона без RDAP - это не поломка, и срать этим в журнал каждый круг
		// незачем
		if r.log != nil && !errors.Is(err, ErrNoServer) && !errors.Is(err, ErrNotFound) {
			r.log("rdap: %s was not resolved: %v", name, err)
		}
		return 0, false
	}
	if r.store != nil {
		_ = r.store.Put(name, registered, now)
	}
	return now.Sub(registered).Hours() / 24, true
}
