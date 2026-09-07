package chain

// Залог донора. Обычный Stake программы требует его подписи, а с биржи никто
// ничего не подпишет - там простой перевод токенов. Поэтому у каждого донора
// свой счёт залога, и башка переносит пришедшее в хранилище сама

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	instructionCreditStake  = 11
	instructionReleaseStake = 12
)

var (
	seedDeposit    = []byte("deposit")
	seedStake      = []byte("stake")
	seedStakeVault = []byte("stake-vault")
)

// stakeLen - длина аккаунта залога в цепочке: тег, владелец, сумма, срок,
// заказанное к выводу и bump
const stakeLen = 1 + 32 + 8 + 8 + 8 + 1

// tagStake - первый байт аккаунта залога. Чужой аккаунт того же размера читать
// как свой нельзя
const tagStake = 4

// Stake - залог донора, как его видит цепочка
type Stake struct {
	Amount uint64
	// Pending - сколько заказано к выводу, Unlock - когда его отдадут
	Pending     uint64
	UnlockAt    int64
	Beneficiary Pubkey
}

// depositKey выводит ключ личного счёта донора из секрета башки.
//
// Обычный аккаунт, а НЕ адрес программы: у PDA нет точки на кривой, и кошельки
// с биржами отбивают такой адрес как невалидный - донор просто не сможет внести
// залог. Ключ нигде не хранится, он всегда выводится заново
func (p *Publisher) depositKey(beneficiary Pubkey) (*Signer, error) {
	mac := hmac.New(sha512.New, p.signer.Secret().Seed())
	mac.Write(seedDeposit)
	mac.Write(beneficiary[:])
	return NewSigner(ed25519.NewKeyFromSeed(mac.Sum(nil)[:ed25519.SeedSize]))
}

// DepositOwner - адрес, на который донор шлёт залог откуда угодно
func (p *Publisher) DepositOwner(beneficiary Pubkey) (Pubkey, error) {
	key, err := p.depositKey(beneficiary)
	if err != nil {
		return Pubkey{}, err
	}
	return key.Public, nil
}

// DepositAccount - счёт, на который донор шлёт залог откуда угодно.
//
// Заводится при первом обращении и платит за него башка: без счёта донору
// некуда слать, а сам он PDA не создаст
func (p *Publisher) DepositAccount(ctx context.Context, mint, beneficiary Pubkey) (Pubkey, error) {
	owner, err := p.DepositOwner(beneficiary)
	if err != nil {
		return Pubkey{}, err
	}
	account, err := AssociatedAccount(owner, mint)
	if err != nil {
		return Pubkey{}, err
	}
	if _, err := p.client.TokenBalance(ctx, account); err == nil {
		return account, nil
	}
	opened, _, err := p.client.OpenAccount(ctx, p.signer, mint, owner)
	if err != nil {
		return Pubkey{}, err
	}
	return opened, nil
}

// StakeOf читает залог из цепочки. Аккаунта нет - значит донор не вносил
// ничего, и это не ошибка
func (p *Publisher) StakeOf(ctx context.Context, beneficiary Pubkey) (Stake, error) {
	account, _, err := FindPDA(p.program, [][]byte{seedStake, beneficiary[:]})
	if err != nil {
		return Stake{}, err
	}
	data, err := p.client.AccountData(ctx, account)
	if errors.Is(err, ErrNoAccount) {
		return Stake{}, nil
	}
	if err != nil {
		return Stake{}, err
	}
	if len(data) < stakeLen || data[0] != tagStake {
		return Stake{}, fmt.Errorf("chain: account %s is not a stake", Base58(account))
	}
	stake := Stake{
		Amount:   binary.LittleEndian.Uint64(data[33:41]),
		UnlockAt: int64(binary.LittleEndian.Uint64(data[41:49])),
		Pending:  binary.LittleEndian.Uint64(data[49:57]),
	}
	copy(stake.Beneficiary[:], data[1:33])
	return stake, nil
}

// PendingDeposit - сколько лежит на личном счету донора и ещё не оприходовано
func (p *Publisher) PendingDeposit(ctx context.Context, mint, beneficiary Pubkey) (uint64, error) {
	owner, err := p.DepositOwner(beneficiary)
	if err != nil {
		return 0, err
	}
	account, err := AssociatedAccount(owner, mint)
	if err != nil {
		return 0, err
	}
	balance, err := p.client.TokenBalance(ctx, account)
	if errors.Is(err, ErrNoAccount) {
		return 0, nil
	}
	return balance, err
}

// ReleaseStake возвращает залог донору на его же кошелёк.
//
// Первый заход заказывает вывод и запускает кулдаун, второй отдаёт деньги.
// Подписывает башка: своей подписи донор нам не давал, он вносил залог обычным
// переводом
func (p *Publisher) ReleaseStake(
	ctx context.Context,
	mint, beneficiary Pubkey,
	amount uint64,
) (string, error) {
	config, _, err := FindPDA(p.program, [][]byte{seedConfig})
	if err != nil {
		return "", err
	}
	stakeAccount, _, err := FindPDA(p.program, [][]byte{seedStake, beneficiary[:]})
	if err != nil {
		return "", err
	}
	vaultOwner, vault, err := p.stakeVault(ctx, mint)
	if err != nil {
		return "", err
	}
	// Деньги уходят на ассоциированный счёт самого донора: кошелёк он назвал
	// заранее, а любой другой его счёт кошельки человеку не покажут
	destination, _, err := p.client.OpenAccount(ctx, p.signer, mint, beneficiary)
	if err != nil {
		return "", err
	}

	payload := make([]byte, 9)
	payload[0] = instructionReleaseStake
	binary.LittleEndian.PutUint64(payload[1:], amount)
	blockhash, err := p.client.LatestBlockhash(ctx)
	if err != nil {
		return "", err
	}
	transaction, err := p.signer.Sign(blockhash, Instruction{
		ProgramID: p.program,
		Accounts: []AccountMeta{
			{Key: p.signer.Public, Signer: true, Writable: true},
			{Key: config},
			{Key: beneficiary},
			{Key: stakeAccount, Writable: true},
			{Key: vault, Writable: true},
			{Key: destination, Writable: true},
			{Key: vaultOwner},
			{Key: TokenProgram},
		},
		Data: payload,
	})
	if err != nil {
		return "", err
	}
	return p.client.Send(ctx, transaction)
}

// stakeVault отдаёт владельца хранилища залогов и его счёт, заводя счёт при
// первом обращении.
//
// Хранилище устроено как казна: PDA только владеет счётом, а сам счёт обычный.
// Счёт по адресу PDA снаружи не создать, и без этого первый же взнос упирался
// в аккаунт, которого нет
func (p *Publisher) stakeVault(ctx context.Context, mint Pubkey) (Pubkey, Pubkey, error) {
	owner, _, err := FindPDA(p.program, [][]byte{seedStakeVault})
	if err != nil {
		return Pubkey{}, Pubkey{}, err
	}
	account, err := AssociatedAccount(owner, mint)
	if err != nil {
		return Pubkey{}, Pubkey{}, err
	}
	if _, err := p.client.TokenBalance(ctx, account); err == nil {
		return owner, account, nil
	}
	opened, _, err := p.client.OpenAccount(ctx, p.signer, mint, owner)
	if err != nil {
		return Pubkey{}, Pubkey{}, err
	}
	return owner, opened, nil
}

// CreditStake переносит пришедшее на личный счёт донора в хранилище залогов.
//
// Две инструкции одной транзакцией: перевод подписывает ключ депозита, учёт -
// башка. Атомарно, поэтому записанный залог всегда обеспечен деньгами
func (p *Publisher) CreditStake(
	ctx context.Context,
	mint, beneficiary Pubkey,
	amount uint64,
) (string, error) {
	if amount == 0 {
		return "", fmt.Errorf("chain: nothing to credit")
	}
	config, _, err := FindPDA(p.program, [][]byte{seedConfig})
	if err != nil {
		return "", err
	}
	depositKey, err := p.depositKey(beneficiary)
	if err != nil {
		return "", err
	}
	deposit, err := AssociatedAccount(depositKey.Public, mint)
	if err != nil {
		return "", err
	}
	_, vault, err := p.stakeVault(ctx, mint)
	if err != nil {
		return "", err
	}
	stakeAccount, _, err := FindPDA(p.program, [][]byte{seedStake, beneficiary[:]})
	if err != nil {
		return "", err
	}

	payload := make([]byte, 9)
	payload[0] = instructionCreditStake
	binary.LittleEndian.PutUint64(payload[1:], amount)
	blockhash, err := p.client.LatestBlockhash(ctx)
	if err != nil {
		return "", err
	}
	transaction, err := p.signer.SignMany(blockhash, []Instruction{
		Transfer(deposit, vault, depositKey.Public, amount),
		{
			ProgramID: p.program,
			Accounts: []AccountMeta{
				{Key: p.signer.Public, Signer: true, Writable: true},
				{Key: config},
				{Key: beneficiary},
				{Key: stakeAccount, Writable: true},
				// System Program - это 32 нуля, отдельной константы под них нет
				{Key: Pubkey{}},
			},
			Data: payload,
		},
	}, map[Pubkey]ed25519.PrivateKey{depositKey.Public: depositKey.Secret()})
	if err != nil {
		return "", err
	}
	return p.client.Send(ctx, transaction)
}
