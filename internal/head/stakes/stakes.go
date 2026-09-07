// Package stakes держит залоги доноров: ловит приход на их личные счета,
// проносит его через программу и отвечает, кому вообще причитаются деньги
package stakes

import (
	"context"
	"sync"
	"time"

	"wingsnet.org/federation/internal/head/chain"
)

// Chain - то, что мы просим у цепочки. Интерфейсом, чтобы сторож проверялся
// без единого похода наружу
type Chain interface {
	DepositOwner(beneficiary chain.Pubkey) (chain.Pubkey, error)
	DepositAccount(ctx context.Context, mint, beneficiary chain.Pubkey) (chain.Pubkey, error)
	PendingDeposit(ctx context.Context, mint, beneficiary chain.Pubkey) (uint64, error)
	CreditStake(ctx context.Context, mint, beneficiary chain.Pubkey, amount uint64) (string, error)
	ReleaseStake(ctx context.Context, mint, beneficiary chain.Pubkey, amount uint64) (string, error)
	StakeOf(ctx context.Context, beneficiary chain.Pubkey) (chain.Stake, error)
}

// Wallets отдаёт кошельки доноров: залог привязан к тому же адресу, на который
// человеку платят
type Wallets interface {
	Wallets() map[string]string
}

// Status - что показать донору про его залог
type Status struct {
	// Deposit - личный адрес, на который донор шлёт залог откуда угодно
	Deposit string
	// Micro - внесено, RequiredMicro - сколько надо, чтобы попасть в выплаты
	Micro         uint64
	RequiredMicro uint64
	// IncomingMicro - пришло на личный счёт и ещё не оприходовано
	IncomingMicro uint64
	// PendingMicro - заказано к выводу, UnlockUnix - когда отдадут
	PendingMicro uint64
	UnlockUnix   int64
}

// Enough отвечает, хватает ли залога для выплат. Нулевой порог не считается
// достигнутым: пустая структура означает "про этого донора мы ничего не знаем",
// а не "он всё внёс"
func (s Status) Enough() bool { return s.RequiredMicro > 0 && s.Micro >= s.RequiredMicro }

// trackTimeout - сколько даём цепочке на фоновый заход. Заведение счёта это
// транзакция, и mainnet отвечает не мгновенно
const trackTimeout = 45 * time.Second

// Watcher следит за залогами
type Watcher struct {
	chain    Chain
	wallets  Wallets
	mint     chain.Pubkey
	required uint64
	log      func(string, ...any)

	mu    sync.RWMutex
	known map[string]Status
	// busy - по каким донорам уже бежит фоновый заход. Без этого каждое
	// открытие экрана плодило бы свою горутину и свою транзакцию
	busy map[string]bool
}

func New(c Chain, wallets Wallets, mint chain.Pubkey, required uint64, log func(string, ...any)) *Watcher {
	return &Watcher{
		chain: c, wallets: wallets, mint: mint, required: required,
		log: log, known: map[string]Status{}, busy: map[string]bool{},
	}
}

// Required - порог входа в платный режим
func (w *Watcher) Required() uint64 { return w.required }

// Staked отвечает, внёс ли донор достаточно. Пока цепочку не опросили, ответ
// отрицательный: платить по неизвестному залогу нельзя
func (w *Watcher) Staked(donorID string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	status, ok := w.known[donorID]
	return ok && status.Micro >= w.required
}

// Status отдаёт последнее известное состояние залога
func (w *Watcher) Status(donorID string) Status {
	w.mu.RLock()
	defer w.mu.RUnlock()
	status, ok := w.known[donorID]
	if !ok {
		status.RequiredMicro = w.required
	}
	return status
}

// Run опрашивает цепочку, пока живёт контекст
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	w.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Refresh(ctx)
		}
	}
}

// Release заказывает вывод залога, а когда кулдаун вышел - отдаёт деньги.
//
// Одна ручка на обе фазы: человек жмёт "забрать" и потом ту же кнопку ещё раз,
// а не разгадывает, чем заказ отличается от выдачи
func (w *Watcher) Release(ctx context.Context, donorID, wallet string, amount uint64) (Status, error) {
	beneficiary, err := chain.ParseKey(wallet)
	if err != nil {
		return w.Status(donorID), err
	}
	signature, err := w.chain.ReleaseStake(ctx, w.mint, beneficiary, amount)
	if err != nil {
		return w.Status(donorID), err
	}
	if w.log != nil {
		w.log("stakes: released %d micro to %s in %s", amount, wallet, signature)
	}
	status, err := w.refreshOne(ctx, wallet)
	if err != nil {
		return w.Status(donorID), nil
	}
	w.mu.Lock()
	w.known[donorID] = status
	w.mu.Unlock()
	return status, nil
}

// Refresh проходит по донорам: что пришло - оприходует, остальное перечитывает
func (w *Watcher) Refresh(ctx context.Context) {
	for donorID, wallet := range w.wallets.Wallets() {
		status, err := w.refreshOne(ctx, wallet)
		if err != nil {
			if w.log != nil {
				w.log("stakes: donor %s is unreadable: %v", donorID, err)
			}
			continue
		}
		w.mu.Lock()
		w.known[donorID] = status
		w.mu.Unlock()
	}
}

// Ensure заводит донору личный счёт, ничего не дожидаясь.
//
// Счёт заводится транзакцией, а её время нам не принадлежит: держать на ней
// запрос панели значит отдать экран на волю mainnet. Поэтому работа уходит в
// фон, а экран показывает то, что известно сейчас
func (w *Watcher) Ensure(donorID, wallet string) {
	if wallet == "" {
		return
	}
	w.mu.Lock()
	if w.busy[donorID] {
		w.mu.Unlock()
		return
	}
	w.busy[donorID] = true
	w.mu.Unlock()

	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.busy, donorID)
			w.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), trackTimeout)
		defer cancel()
		status, err := w.refreshOne(ctx, wallet)
		if err != nil {
			if w.log != nil {
				w.log("stakes: donor %s is unreadable: %v", donorID, err)
			}
			return
		}
		w.mu.Lock()
		w.known[donorID] = status
		w.mu.Unlock()
	}()
}

func (w *Watcher) refreshOne(ctx context.Context, wallet string) (Status, error) {
	status := Status{RequiredMicro: w.required}
	beneficiary, err := chain.ParseKey(wallet)
	if err != nil {
		return status, err
	}
	// Человеку показываем ВЛАДЕЛЬЦА, а не токен-счёт: кошельки и биржи шлют на
	// адрес владельца и сами находят его счёт, а на токен-счёт отвечают
	// "invalid address"
	owner, err := w.chain.DepositOwner(beneficiary)
	if err != nil {
		return status, err
	}
	status.Deposit = chain.Base58(owner)
	// Счёт всё равно заводим заранее: биржа, которая не умеет создавать его
	// сама, иначе упрётся в пустоту
	if _, err := w.chain.DepositAccount(ctx, w.mint, beneficiary); err != nil {
		return status, err
	}

	incoming, err := w.chain.PendingDeposit(ctx, w.mint, beneficiary)
	if err != nil {
		return status, err
	}
	// Пришедшее уносим в хранилище сразу: пока оно лежит на личном счету, это
	// ещё не залог, и отнять за вранье с него нечего
	if incoming > 0 {
		signature, err := w.chain.CreditStake(ctx, w.mint, beneficiary, incoming)
		if err != nil {
			status.IncomingMicro = incoming
			return status, err
		}
		if w.log != nil {
			w.log("stakes: credited %d micro to %s in %s", incoming, wallet, signature)
		}
	}

	stake, err := w.chain.StakeOf(ctx, beneficiary)
	if err != nil {
		return status, err
	}
	status.Micro = stake.Amount
	status.PendingMicro = stake.Pending
	status.UnlockUnix = stake.UnlockAt
	return status, nil
}
