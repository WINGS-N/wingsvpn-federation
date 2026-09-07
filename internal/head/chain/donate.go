package chain

// Донат юзера уходит в казну не переводом, а инструкцией программы: только так
// с него удерживается доля оператора. Спонсорский взнос идёт прямым переводом и
// программу не зовёт, поэтому и удерживать с него нечего

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

const instructionDonate = 9

// Donate отправляет сумму через программу: доля уходит на счёт комиссии,
// остальное в казну. Платит и подписывает башка, потому что деньги уже лежат на
// её приёмном счету
func (p *Publisher) Donate(ctx context.Context, mint Pubkey, amount uint64) (string, error) {
	if amount == 0 {
		return "", fmt.Errorf("chain: nothing to donate")
	}
	config, _, err := FindPDA(p.program, [][]byte{seedConfig})
	if err != nil {
		return "", err
	}
	feeState, _, err := FindPDA(p.program, [][]byte{seedFee})
	if err != nil {
		return "", err
	}
	treasuryOwner, _, err := FindPDA(p.program, [][]byte{seedTreasury})
	if err != nil {
		return "", err
	}
	from, err := p.client.TokenAccountOf(ctx, p.signer.Public, mint)
	if err != nil {
		return "", err
	}
	treasury, err := p.client.TokenAccountOf(ctx, treasuryOwner, mint)
	if err != nil {
		return "", err
	}
	feeAccount, err := p.client.TokenAccountOf(ctx, feeState, mint)
	if err != nil {
		return "", err
	}

	payload := make([]byte, 9)
	payload[0] = instructionDonate
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
			{Key: feeState},
			{Key: from, Writable: true},
			{Key: treasury, Writable: true},
			{Key: feeAccount, Writable: true},
			{Key: TokenProgram},
		},
		Data: payload,
	})
	if err != nil {
		return "", err
	}
	return p.client.Send(ctx, transaction)
}

// SweepDonations уносит в казну всё, что накопилось на приёмном счету.
//
// Деньги юзеров приходят обычным переводом с заметкой, и до этого места они
// лежат мимо программы: пока их не пронесли через Donate, доноры их не видят
func (p *Publisher) SweepDonations(ctx context.Context, mint Pubkey) (string, uint64, error) {
	from, err := p.client.TokenAccountOf(ctx, p.signer.Public, mint)
	if errors.Is(err, ErrNoAccount) {
		// Счёта нет - значит и денег никто не заносил. Это тишина, а не поломка
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	amount, err := p.client.TokenBalance(ctx, from)
	if err != nil {
		return "", 0, err
	}
	if amount == 0 {
		return "", 0, nil
	}
	signature, err := p.Donate(ctx, mint, amount)
	if err != nil {
		return "", 0, err
	}
	return signature, amount, nil
}
