package chain

// Токен-программа своими руками.
//
// Чужой CLI для этого не нужен нахуй: инструкций всего три, а spl-token-cli не
// собирается на свежих крейтах и тянет за собой полчаса компиляции

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"

	"wingsnet.org/federation/internal/head/payout"
)

// Размеры аккаунтов зашиты в формат токен-программы
const (
	MintLen    = 82
	AccountLen = 165
)

// Номера инструкций токен-программы
const (
	ixInitializeMint    = 0
	ixInitializeAccount = 1
	ixTransfer          = 3
	ixMintTo            = 7
)

// TokenProgram и RentSysvar - адреса, к которым обращается токен-программа
var (
	TokenProgram = MustKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	RentSysvar   = MustKey("SysvarRent111111111111111111111111111111111")
)

// Treasury - что получилось после заведения казны
type Treasury struct {
	Mint     Pubkey
	Account  Pubkey
	Owner    Pubkey
	Decimals uint8
}

// CreateTreasury заводит минт и казну под указанным владельцем, потом чеканит в
// неё первую сумму.
//
// Владелец - PDA программы выплат: сам он токен-аккаунтом быть не может, тот
// принадлежит токен-программе, поэтому казна это отдельный аккаунт
func (c *Client) CreateTreasury(
	ctx context.Context,
	payer *Signer,
	owner Pubkey,
	decimals uint8,
	amount uint64,
) (Treasury, string, error) {
	mint, mintSecret, err := NewAccountKey()
	if err != nil {
		return Treasury{}, "", err
	}
	account, accountSecret, err := NewAccountKey()
	if err != nil {
		return Treasury{}, "", err
	}
	mintRent, err := c.MinimumBalance(ctx, MintLen)
	if err != nil {
		return Treasury{}, "", err
	}
	accountRent, err := c.MinimumBalance(ctx, AccountLen)
	if err != nil {
		return Treasury{}, "", err
	}

	initMint := []byte{ixInitializeMint, decimals}
	initMint = append(initMint, payer.Public[:]...)
	// Ноль вместо freeze authority: замораживать чужие деньги мы не собираемся
	initMint = append(initMint, 0)

	instructions := []Instruction{
		CreateAccount(payer.Public, mint, mintRent, MintLen, TokenProgram),
		{
			ProgramID: TokenProgram,
			Accounts:  []AccountMeta{{Key: mint, Writable: true}, {Key: RentSysvar}},
			Data:      initMint,
		},
		CreateAccount(payer.Public, account, accountRent, AccountLen, TokenProgram),
		InitAccount(account, mint, owner),
	}
	if amount > 0 {
		instructions = append(instructions, MintTo(mint, account, payer.Public, amount))
	}

	blockhash, err := c.LatestBlockhash(ctx)
	if err != nil {
		return Treasury{}, "", err
	}
	tx, err := payer.SignMany(blockhash, instructions, map[Pubkey]ed25519.PrivateKey{
		mint:    mintSecret,
		account: accountSecret,
	})
	if err != nil {
		return Treasury{}, "", err
	}
	signature, err := c.Send(ctx, tx)
	if err != nil {
		return Treasury{}, "", err
	}
	return Treasury{Mint: mint, Account: account, Owner: owner, Decimals: decimals}, signature, nil
}

// AssociatedTokenProgram - программа ассоциированных счетов
var AssociatedTokenProgram = MustKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")

// AssociatedAccount - тот самый счёт, куда шлют деньги все кошельки и биржи.
//
// Адрес выводится из владельца и минта, поэтому один и тот же у всех: свой
// аккаунт вместо него означает, что кошелёк человека покажет пустоту, а деньги
// осядут там, куда никто не смотрит
func AssociatedAccount(owner, mint Pubkey) (Pubkey, error) {
	account, _, err := FindPDA(AssociatedTokenProgram, [][]byte{owner[:], TokenProgram[:], mint[:]})
	return account, err
}

// OpenAccount заводит человеку ассоциированный счёт под токен.
//
// Idempotent: счёт уже есть - инструкция молча соглашается, а не валит всю
// транзакцию. Это важно, потому что завести его мог кто угодно раньше нас
func (c *Client) OpenAccount(
	ctx context.Context,
	payer *Signer,
	mint, owner Pubkey,
) (Pubkey, string, error) {
	account, err := AssociatedAccount(owner, mint)
	if err != nil {
		return Pubkey{}, "", err
	}
	blockhash, err := c.LatestBlockhash(ctx)
	if err != nil {
		return Pubkey{}, "", err
	}
	tx, err := payer.Sign(blockhash, CreateAssociatedAccount(payer.Public, account, owner, mint))
	if err != nil {
		return Pubkey{}, "", err
	}
	signature, err := c.Send(ctx, tx)
	if err != nil {
		return Pubkey{}, "", err
	}
	return account, signature, nil
}

// CreateAssociatedAccount - инструкция CreateIdempotent ассоциированной
// программы. Тег 1, полезной нагрузки у неё нет
func CreateAssociatedAccount(payer, account, owner, mint Pubkey) Instruction {
	return Instruction{
		ProgramID: AssociatedTokenProgram,
		Accounts: []AccountMeta{
			{Key: payer, Signer: true, Writable: true},
			{Key: account, Writable: true},
			{Key: owner},
			{Key: mint},
			{Key: Pubkey{}},
			{Key: TokenProgram},
		},
		Data: []byte{1},
	}
}

// CreateAccount - заведение аккаунта через System Program
func CreateAccount(payer, target Pubkey, lamports uint64, space int, owner Pubkey) Instruction {
	data := make([]byte, 0, 52)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint64(data, lamports)
	data = binary.LittleEndian.AppendUint64(data, uint64(space))
	data = append(data, owner[:]...)
	return Instruction{
		ProgramID: Pubkey{},
		Accounts: []AccountMeta{
			{Key: payer, Signer: true, Writable: true},
			{Key: target, Signer: true, Writable: true},
		},
		Data: data,
	}
}

// InitAccount привязывает заведённый аккаунт к минту и владельцу
func InitAccount(account, mint, owner Pubkey) Instruction {
	return Instruction{
		ProgramID: TokenProgram,
		Accounts: []AccountMeta{
			{Key: account, Writable: true},
			{Key: mint},
			{Key: owner},
			{Key: RentSysvar},
		},
		Data: []byte{ixInitializeAccount},
	}
}

// MintTo чеканит в аккаунт. Право чеканки у того, кто завёл минт
func MintTo(mint, account, authority Pubkey, amount uint64) Instruction {
	data := make([]byte, 0, 9)
	data = append(data, ixMintTo)
	data = binary.LittleEndian.AppendUint64(data, amount)
	return Instruction{
		ProgramID: TokenProgram,
		Accounts: []AccountMeta{
			{Key: mint, Writable: true},
			{Key: account, Writable: true},
			{Key: authority, Signer: true},
		},
		Data: data,
	}
}

// NewAccountKey - ключ для нового аккаунта. Он подписывает своё создание, иначе
// цепочка отобьёт транзакцию
func NewAccountKey() (Pubkey, ed25519.PrivateKey, error) {
	public, secret, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Pubkey{}, nil, err
	}
	var key Pubkey
	copy(key[:], public)
	return key, secret, nil
}

// MustKey разбирает адрес из base58. Паникует на кривом входе: адреса тут
// зашиты в код, и кривой означает опечатку, а не чужой ввод
func MustKey(text string) Pubkey {
	key, err := ParseKey(text)
	if err != nil {
		panic("chain: bad address " + text)
	}
	return key
}

// ParseKey разбирает адрес, введённый человеком. MustKey тут не годится: кривой
// кошелёк в поле панели уронил бы башку целиком
func ParseKey(text string) (Pubkey, error) {
	raw, err := payout.DecodeBase58(text)
	if err != nil {
		return Pubkey{}, err
	}
	if len(raw) != 32 {
		return Pubkey{}, fmt.Errorf("chain: address %q is %d bytes, not 32", text, len(raw))
	}
	var key Pubkey
	copy(key[:], raw)
	return key, nil
}

// Base58 печатает адрес так, как его показывают людям
func Base58(key Pubkey) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	num := new(big.Int).SetBytes(key[:])
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	out := make([]byte, 0, 44)
	for num.Cmp(zero) > 0 {
		num.DivMod(num, radix, mod)
		out = append([]byte{alphabet[mod.Int64()]}, out...)
	}
	for _, b := range key {
		if b != 0 {
			break
		}
		out = append([]byte{alphabet[0]}, out...)
	}
	return string(out)
}

// Transfer двигает токены между счетами одного минта. Подписывает владелец
// счёта-источника, а не тот, кому шлют
func Transfer(from, to, owner Pubkey, amount uint64) Instruction {
	data := make([]byte, 0, 9)
	data = append(data, ixTransfer)
	data = binary.LittleEndian.AppendUint64(data, amount)
	return Instruction{
		ProgramID: TokenProgram,
		Accounts: []AccountMeta{
			{Key: from, Writable: true},
			{Key: to, Writable: true},
			{Key: owner, Signer: true},
		},
		Data: data,
	}
}

// TokenAccountOf ищет счёт владельца на этом минте.
//
// Счетов на один минт бывает несколько: свой мы заводим сами, а кошелёк
// отправителя кладёт деньги в ассоциированный. Поэтому берём не первый попавшийся,
// а тот, где лежат деньги - иначе перевод уходит с пустого счёта
func (c *Client) TokenAccountOf(ctx context.Context, owner, mint Pubkey) (Pubkey, error) {
	var out struct {
		Value []struct {
			Pubkey  string `json:"pubkey"`
			Account struct {
				Data struct {
					Parsed struct {
						Info struct {
							TokenAmount struct {
								Amount string `json:"amount"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	params := []any{
		Base58(owner),
		map[string]any{"mint": Base58(mint)},
		map[string]any{"encoding": "jsonParsed"},
	}
	if err := c.call(ctx, "getTokenAccountsByOwner", params, &out); err != nil {
		return Pubkey{}, err
	}
	if len(out.Value) == 0 {
		return Pubkey{}, ErrNoAccount
	}
	best, most := out.Value[0].Pubkey, uint64(0)
	for _, row := range out.Value {
		amount, err := strconv.ParseUint(row.Account.Data.Parsed.Info.TokenAmount.Amount, 10, 64)
		if err == nil && amount > most {
			best, most = row.Pubkey, amount
		}
	}
	return MustKey(best), nil
}

// TokenBalance читает баланс токен-аккаунта. Владелец и минт лежат в тех же
// данных, но тут нужна только сумма
func (c *Client) TokenBalance(ctx context.Context, account Pubkey) (uint64, error) {
	var out struct {
		Value struct {
			Amount string `json:"amount"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getTokenAccountBalance", []any{Base58(account)}, &out); err != nil {
		return 0, err
	}
	var amount uint64
	if _, err := fmt.Sscanf(out.Value.Amount, "%d", &amount); err != nil {
		return 0, err
	}
	return amount, nil
}
