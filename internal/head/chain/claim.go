package chain

// Выплата донору: башка клеймит за него сама.
//
// Подпись донора тут не нужна - программа платит строго владельцу листа, кто бы
// ни прислал транзакцию. Иначе донору пришлось бы держать SOL на комиссию и
// лезть в терминал с пруфом, а это не выплата, а квест

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"wingsnet.org/federation/internal/head/payout"
)

// Номер инструкции клейма в программе выплат
const instructionClaim = 2

// Payment - одна выплата: кому, сколько и по какому пути в дереве
type Payment struct {
	Wallet Pubkey
	// Index - номер листа в дереве: по нему цепочка ставит бит выплаченного
	Index  uint32
	Amount uint64
	Proof  [][32]byte
	// Token - токен-аккаунт донора, куда придут деньги. Его владельцем обязан
	// быть Wallet, иначе программа отобьёт выплату
	Token Pubkey
}

// Claim платит одному донору за одну эпоху
func (p *Publisher) Claim(ctx context.Context, epoch uint64, payment Payment) (string, error) {
	if payment.Amount == 0 {
		return "", fmt.Errorf("chain: empty payout in epoch %d", epoch)
	}
	number := make([]byte, 8)
	binary.LittleEndian.PutUint64(number, epoch)

	config, _, err := FindPDA(p.program, [][]byte{seedConfig})
	if err != nil {
		return "", err
	}
	epochPDA, _, err := FindPDA(p.program, [][]byte{seedEpoch, number})
	if err != nil {
		return "", err
	}
	treasuryAuthority, _, err := FindPDA(p.program, [][]byte{seedTreasury})
	if err != nil {
		return "", err
	}

	data := make([]byte, 0, 1+8+4+8+4+len(payment.Proof)*32)
	data = append(data, instructionClaim)
	data = binary.LittleEndian.AppendUint64(data, epoch)
	data = binary.LittleEndian.AppendUint32(data, payment.Index)
	data = binary.LittleEndian.AppendUint64(data, payment.Amount)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(payment.Proof)))
	for _, step := range payment.Proof {
		data = append(data, step[:]...)
	}

	blockhash, err := p.client.LatestBlockhash(ctx)
	if err != nil {
		return "", err
	}
	tx, err := p.signer.Sign(blockhash, Instruction{
		ProgramID: p.program,
		Accounts: []AccountMeta{
			{Key: payment.Wallet},
			{Key: p.signer.Public, Signer: true, Writable: true},
			{Key: config},
			{Key: epochPDA, Writable: true},
			{Key: p.treasury, Writable: true},
			{Key: payment.Token, Writable: true},
			{Key: TokenProgram},
			{Key: Pubkey{}},
			{Key: treasuryAuthority},
		},
		Data: data,
	})
	if err != nil {
		return "", err
	}
	return p.client.Send(ctx, tx)
}

// PaymentsFrom собирает выплаты по эпохе: кошелёк, сумма и пруф из того же
// дерева, что уехало корнем в цепочку
func PaymentsFrom(epoch *payout.Epoch, tokenOf func(wallet string) (Pubkey, bool)) ([]Payment, error) {
	out := make([]Payment, 0, len(epoch.Leaves))
	for _, leaf := range epoch.Leaves {
		token, ok := tokenOf(leaf.Address)
		if !ok {
			// Донор не завёл счёт под токен: платить некуда, и это не повод
			// ронять всю эпоху
			continue
		}
		proof, err := epoch.Proof(leaf.Address)
		if err != nil {
			return nil, err
		}
		index, ok := epoch.IndexOf(leaf.Address)
		if !ok {
			return nil, fmt.Errorf("chain: leaf %s is missing from the tree", leaf.Address)
		}
		out = append(out, Payment{
			Wallet: MustKey(leaf.Address),
			Index:  index,
			Amount: uint64(leaf.Amount),
			Proof:  proof,
			Token:  token,
		})
	}
	return out, nil
}

// PayEveryone платит всем, кому причиталось в этой эпохе.
//
// Провал одной выплаты не роняет остальные: корень уже в цепочке, а недоплата
// добирается следующим заходом. Донор без заведённого счёта под токен просто
// пропускается - платить ему пока некуда
func (p *Publisher) PayEveryone(ctx context.Context, epoch *payout.Epoch) (int, error) {
	if p.tokens == nil {
		return 0, fmt.Errorf("chain: no idea where to pay the donors")
	}
	payments, err := PaymentsFrom(epoch, p.tokens)
	if err != nil {
		return 0, err
	}
	paid := 0
	var failures error
	for _, payment := range payments {
		signature, err := p.Claim(ctx, epoch.Number, payment)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", Base58(payment.Wallet), err))
			continue
		}
		paid++
		if p.paidSink != nil {
			p.paidSink(epoch.Number, Base58(payment.Wallet), payment.Amount, signature)
		}
		if p.log != nil {
			p.log("chain: paid %d to %s as %s", payment.Amount, Base58(payment.Wallet), signature)
		}
	}
	return paid, failures
}

// SetPaidSink говорит, куда записывать состоявшиеся выплаты: без ссылки на
// транзакцию донор видит цифру, а не деньги
func (p *Publisher) SetPaidSink(sink func(epoch uint64, wallet string, micro uint64, tx string)) {
	p.paidSink = sink
}

// SetTokens говорит, на какой счёт платить каждому донору
func (p *Publisher) SetTokens(tokenOf func(wallet string) (Pubkey, bool)) { p.tokens = tokenOf }
