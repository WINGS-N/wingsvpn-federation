package dialpick

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeResolver struct {
	addrs []string
	err   error
	calls int
}

func (f *fakeResolver) LookupHost(context.Context, string) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs, nil
}

func pickerAt(endpoint string, resolver Resolver, now time.Time) *Picker {
	p := New(endpoint)
	p.SetResolver(resolver)
	p.now = func() time.Time { return now }
	return p
}

// Балансировщик подсунул недоступный узел - идём к следующему, а не ложимся
func TestABadAddressIsSkipped(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	p := pickerAt("head.example:30310", resolver, time.Unix(1_700_000_000, 0))

	first := p.Next(context.Background())
	p.Failed(first)
	second := p.Next(context.Background())
	if first == second {
		t.Fatalf("после отказа вернули тот же адрес: %s", first)
	}
}

// Рабочий адрес держим, чтобы ротация не дёргала нас на каждое подключение
func TestAWorkingAddressIsKept(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	now := time.Unix(1_700_000_000, 0)
	p := pickerAt("head.example:30310", resolver, now)

	p.Worked("10.0.0.2:30310")
	for i := 0; i < 5; i++ {
		if got := p.Next(context.Background()); got != "10.0.0.2:30310" {
			t.Fatalf("сорвались с рабочего адреса на %s", got)
		}
	}
}

// Балансировщика уважаем: убрал адрес из пула - отпускаем, про переезд и
// обслуживание он знает, а мы нет
func TestAnAddressDroppedFromThePoolIsReleased(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	now := time.Unix(1_700_000_000, 0)
	p := pickerAt("head.example:30310", resolver, now)
	p.Worked("10.0.0.2:30310")

	// Пул сменился, нашего адреса там больше нет
	resolver.addrs = []string{"10.0.0.7"}
	p.now = func() time.Time { return now.Add(recheckEvery + time.Minute) }

	if got := p.Next(context.Background()); got != "10.0.0.7:30310" {
		t.Fatalf("держимся за адрес, который балансировщик убрал: %s", got)
	}
	if p.Sticky() != "" {
		t.Fatalf("старый адрес всё ещё считается рабочим: %s", p.Sticky())
	}
}

// Пока адрес в пуле, перерезолв не должен нас с него сбивать
func TestStayingWhileTheBalancerStillOffersIt(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	now := time.Unix(1_700_000_000, 0)
	p := pickerAt("head.example:30310", resolver, now)
	p.Worked("10.0.0.2:30310")

	p.now = func() time.Time { return now.Add(recheckEvery + time.Minute) }
	if got := p.Next(context.Background()); got != "10.0.0.2:30310" {
		t.Fatalf("ушли с адреса, который всё ещё в пуле: %s", got)
	}
}

// Резолв отвалился - идём по последнему рабочему, а не в никуда
func TestBrokenResolutionFallsBackToWhatWorked(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.1"}}
	now := time.Unix(1_700_000_000, 0)
	p := pickerAt("head.example:30310", resolver, now)
	p.Worked("10.0.0.1:30310")

	resolver.err = errors.New("dns down")
	p.now = func() time.Time { return now.Add(recheckEvery + time.Minute) }
	if got := p.Next(context.Background()); got != "10.0.0.1:30310" {
		t.Fatalf("при мёртвом резолве пошли не туда: %s", got)
	}
}

// Адрес вместо имени резолвить незачем
func TestAPlainAddressIsUsedAsIs(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.9"}}
	p := pickerAt("203.0.113.5:30310", resolver, time.Unix(1_700_000_000, 0))
	if got := p.Next(context.Background()); got != "203.0.113.5:30310" {
		t.Fatalf("тронули голый адрес: %s", got)
	}
	if resolver.calls != 0 {
		t.Fatal("зачем-то полезли в dns за адресом, который уже адрес")
	}
}

// Все адреса отбраковали - начинаем круг заново, они могли ожить
func TestTheCycleRestartsWhenEverythingFailed(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	p := pickerAt("head.example:30310", resolver, time.Unix(1_700_000_000, 0))

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		addr := p.Next(context.Background())
		seen[addr] = true
		p.Failed(addr)
	}
	if len(seen) != 2 {
		t.Fatalf("перебрали не все адреса: %+v", seen)
	}
}

// Башку закрывают целиком, и тогда все её адреса мертвы одинаково. Перебор
// обязан уйти на ноды, а не топтаться по заблокированному имени
func TestRelaysTakeOverWhenEveryDirectAddressIsDead(t *testing.T) {
	p := New("federation.example:9310")
	p.SetResolver(&fakeResolver{addrs: []string{"1.1.1.1", "2.2.2.2"}})
	p.SetRelays([]string{"9.9.9.9:30311", "8.8.8.8:30311"})

	ctx := context.Background()
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		addr := p.Next(ctx)
		seen[addr] = true
		p.Failed(addr)
	}
	if !seen["1.1.1.1:9310"] || !seen["2.2.2.2:9310"] {
		t.Fatalf("прямые адреса не перебрали: %v", seen)
	}
	if !seen["9.9.9.9:30311"] && !seen["8.8.8.8:30311"] {
		t.Fatalf("до нод так и не дошли: %v", seen)
	}
}

// Пока прямой путь жив, через ноду ходить незачем: это лишнее звено и лишний
// повод для чужой ноды видеть наш трафик
func TestRelaysStayUnusedWhileTheHeadAnswers(t *testing.T) {
	p := New("federation.example:9310")
	p.SetResolver(&fakeResolver{addrs: []string{"1.1.1.1"}})
	p.SetRelays([]string{"9.9.9.9:30311"})

	ctx := context.Background()
	first := p.Next(ctx)
	p.Worked(first)
	if got := p.Next(ctx); got != "1.1.1.1:9310" {
		t.Fatalf("ушли с рабочего прямого пути на %q", got)
	}
}

// Адрес, на котором соединение встаёт и тут же дохнет, обязан браковаться:
// иначе перебор липнет к нему и до нод не доходит никогда
func TestAShortLivedAddressIsDropped(t *testing.T) {
	p := New("federation.example:9310")
	p.SetResolver(&fakeResolver{addrs: []string{"1.1.1.1", "2.2.2.2"}})

	ctx := context.Background()
	first := p.Next(ctx)
	// Дозвон удался, но сессия не прожила ничего полезного
	p.Failed(first)
	if second := p.Next(ctx); second == first {
		t.Fatalf("остались на мёртвом адресе %q", second)
	}
}
