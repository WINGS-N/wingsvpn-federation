package stakes

import (
	"context"
	"errors"
	"testing"

	"wingsnet.org/federation/internal/head/chain"
)

type fakeChain struct {
	incoming  uint64
	staked    uint64
	credited  uint64
	creditErr error
}

func (f *fakeChain) DepositOwner(chain.Pubkey) (chain.Pubkey, error) {
	var key chain.Pubkey
	key[0] = 3
	return key, nil
}

func (f *fakeChain) DepositAccount(context.Context, chain.Pubkey, chain.Pubkey) (chain.Pubkey, error) {
	var key chain.Pubkey
	key[0] = 7
	return key, nil
}

func (f *fakeChain) PendingDeposit(context.Context, chain.Pubkey, chain.Pubkey) (uint64, error) {
	return f.incoming, nil
}

func (f *fakeChain) CreditStake(_ context.Context, _, _ chain.Pubkey, amount uint64) (string, error) {
	if f.creditErr != nil {
		return "", f.creditErr
	}
	f.credited += amount
	f.staked += amount
	f.incoming = 0
	return "signature", nil
}

func (f *fakeChain) ReleaseStake(_ context.Context, _, _ chain.Pubkey, amount uint64) (string, error) {
	if amount > f.staked {
		return "", errors.New("залога столько нет")
	}
	f.staked -= amount
	return "signature", nil
}

func (f *fakeChain) StakeOf(context.Context, chain.Pubkey) (chain.Stake, error) {
	return chain.Stake{Amount: f.staked}, nil
}

// blockingChain держит первый заход, пока тест не отпустит
type blockingChain struct {
	start   chan struct{}
	release chan struct{}
}

func (b *blockingChain) DepositOwner(chain.Pubkey) (chain.Pubkey, error) {
	return chain.Pubkey{}, nil
}

func (b *blockingChain) DepositAccount(context.Context, chain.Pubkey, chain.Pubkey) (chain.Pubkey, error) {
	b.start <- struct{}{}
	<-b.release
	return chain.Pubkey{}, nil
}

func (b *blockingChain) PendingDeposit(context.Context, chain.Pubkey, chain.Pubkey) (uint64, error) {
	return 0, nil
}

func (b *blockingChain) CreditStake(context.Context, chain.Pubkey, chain.Pubkey, uint64) (string, error) {
	return "", nil
}

func (b *blockingChain) ReleaseStake(context.Context, chain.Pubkey, chain.Pubkey, uint64) (string, error) {
	return "", nil
}

func (b *blockingChain) StakeOf(context.Context, chain.Pubkey) (chain.Stake, error) {
	return chain.Stake{}, nil
}

type oneWallet struct{ wallet string }

func (o oneWallet) Wallets() map[string]string { return map[string]string{"admin-1": o.wallet} }

// Настоящий кошелёк, чтобы разбор base58 шёл как в бою
const wallet = "62aCGMRdKbiVN1iPccjYh4yUqi3DYHg7sDko6STGoPrb"

func TestДепозитПревращаетсяВЗалог(t *testing.T) {
	fake := &fakeChain{incoming: 60_000_000}
	watcher := New(fake, oneWallet{wallet}, chain.Pubkey{}, 50_000_000, nil)

	watcher.Refresh(context.Background())

	if fake.credited != 60_000_000 {
		t.Fatalf("пришедшее не оприходовано: %d", fake.credited)
	}
	if !watcher.Staked("admin-1") {
		t.Fatal("залога хватает, а донор всё равно без выплат")
	}
}

// Половина залога это не залог: платить по нему значит отдать больше, чем можно
// отнять за вранье
func TestНедобранныйЗалогНеПускаетВВыплаты(t *testing.T) {
	fake := &fakeChain{incoming: 10_000_000}
	watcher := New(fake, oneWallet{wallet}, chain.Pubkey{}, 50_000_000, nil)

	watcher.Refresh(context.Background())

	if watcher.Staked("admin-1") {
		t.Fatal("донор с недобранным залогом попал в выплаты")
	}
	if status := watcher.Status("admin-1"); status.Micro != 10_000_000 {
		t.Fatalf("внесённое потерялось: %+v", status)
	}
}

// Экран открывают часто, а счёт заводится транзакцией: второй заход, пока
// работает первый, не должен плодить ни горутину, ни транзакцию
func TestФоновыйЗаходНеДублируется(t *testing.T) {
	release := make(chan struct{})
	fake := &blockingChain{start: make(chan struct{}, 8), release: release}
	watcher := New(fake, oneWallet{wallet}, chain.Pubkey{}, 20_000_000, nil)

	for i := 0; i < 5; i++ {
		watcher.Ensure("admin-1", wallet)
	}
	<-fake.start
	close(release)

	if got := len(fake.start); got != 0 {
		t.Fatalf("фоновых заходов больше одного: %d лишних", got)
	}
}

// Забрать больше, чем внесено, нельзя: иначе хранилище чужих залогов уедет
// первому же, кто попросит побольше
func TestВыводБольшеЗалогаОтбивается(t *testing.T) {
	fake := &fakeChain{staked: 20_000_000}
	watcher := New(fake, oneWallet{wallet}, chain.Pubkey{}, 20_000_000, nil)
	watcher.Refresh(context.Background())

	if _, err := watcher.Release(context.Background(), "admin-1", wallet, 50_000_000); err == nil {
		t.Fatal("вывод сверх залога прошёл")
	}
	if !watcher.Staked("admin-1") {
		t.Fatal("неудачный вывод съел залог")
	}
}

// Кошелькам отдаём адрес владельца: токен-счёт они отбивают как невалидный
func TestПоказываемВладельцаАНеТокенСчёт(t *testing.T) {
	fake := &fakeChain{}
	watcher := New(fake, oneWallet{wallet}, chain.Pubkey{}, 20_000_000, nil)
	watcher.Refresh(context.Background())

	var owner chain.Pubkey
	owner[0] = 3
	if got := watcher.Status("admin-1").Deposit; got != chain.Base58(owner) {
		t.Fatalf("показали %s, а кошелёк ждёт владельца %s", got, chain.Base58(owner))
	}
}

// Пока цепочку не спросили, залог неизвестен, а неизвестный залог это не залог
func TestНеопрошенныйДонорНеСчитаетсяВнёсшим(t *testing.T) {
	watcher := New(&fakeChain{staked: 99_000_000}, oneWallet{wallet}, chain.Pubkey{}, 50_000_000, nil)

	if watcher.Staked("admin-1") {
		t.Fatal("залог засчитан до первого похода в цепочку")
	}
	if got := watcher.Status("admin-1").RequiredMicro; got != 50_000_000 {
		t.Fatalf("порог не назван: %d", got)
	}
}

// Отказ цепочки не должен выглядеть как внесённый залог
func TestОблом_зачисления_не_даёт_выплат(t *testing.T) {
	fake := &fakeChain{incoming: 70_000_000, creditErr: errors.New("rpc сдох")}
	watcher := New(fake, oneWallet{wallet}, chain.Pubkey{}, 50_000_000, nil)

	watcher.Refresh(context.Background())

	if watcher.Staked("admin-1") {
		t.Fatal("непрошедшее зачисление засчитано как залог")
	}
}
