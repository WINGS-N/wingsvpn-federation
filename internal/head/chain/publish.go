package chain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"wingsnet.org/federation/internal/head/payout"
)

// Номера инструкций программы выплат. Держим их тут, потому что расходятся они
// молча: программа примет чужой номер как свой и сделает не то нахуй
const (
	instructionPublishEpoch = 1
)

// Семена PDA. Один в один с программой: разъедутся - адрес не сойдётся, и
// цепочка отобьёт транзакцию
var (
	seedConfig   = []byte("config")
	seedEpoch    = []byte("epoch")
	seedTreasury = []byte("treasury")
	seedFee      = []byte("fee")
)

// systemProgram - адрес System Program, он же 32 нуля. Программа зовёт его,
// чтобы завести аккаунт эпохи: PDA снаружи создать некому

// Publisher публикует эпохи в цепочку
type Publisher struct {
	client  *Client
	signer  *Signer
	program Pubkey
	log     func(string, ...any)
	// treasury - токен-аккаунт казны. Он не выводится из семян: казна это
	// обычный счёт, а PDA только его владелец
	treasury Pubkey
	// tokens - на какой счёт платить донору. Кошелёк из листа сам по себе
	// токены не держит, деньги идут на его токен-аккаунт
	tokens func(wallet string) (Pubkey, bool)
	// paidSink принимает состоявшиеся выплаты, чтобы они легли в выписку
	paidSink func(epoch uint64, wallet string, micro uint64, tx string)
}

// SetTreasury указывает, из какого счёта платить
func (p *Publisher) SetTreasury(account Pubkey) { p.treasury = account }

func NewPublisher(client *Client, signer *Signer, program Pubkey, log func(string, ...any)) *Publisher {
	return &Publisher{client: client, signer: signer, program: program, log: log}
}

// Publish отправляет корень эпохи. Возвращает подпись транзакции: по ней потом
// видно, что публикация правда доехала
func (p *Publisher) Publish(ctx context.Context, epoch *payout.Epoch) (string, error) {
	if epoch == nil {
		return "", errors.New("chain: nothing to publish")
	}
	config, _, err := FindPDA(p.program, [][]byte{seedConfig})
	if err != nil {
		return "", err
	}
	number := make([]byte, 8)
	binary.LittleEndian.PutUint64(number, epoch.Number)
	epochPDA, _, err := FindPDA(p.program, [][]byte{seedEpoch, number})
	if err != nil {
		return "", err
	}

	data := make([]byte, 0, 1+8+32+8+4)
	data = append(data, instructionPublishEpoch)
	data = append(data, number...)
	data = append(data, epoch.Root[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(epoch.Total))
	// Число листьев: под них программа выделяет битмап выплаченного. Отдельный
	// аккаунт на каждую выплату стоил ренты за каждого донора и не возвращался
	data = binary.LittleEndian.AppendUint32(data, uint32(len(epoch.Leaves)))

	blockhash, err := p.client.LatestBlockhash(ctx)
	if err != nil {
		return "", err
	}
	transaction, err := p.signer.Sign(blockhash, Instruction{
		ProgramID: p.program,
		Accounts: []AccountMeta{
			{Key: p.signer.Public, Signer: true, Writable: true},
			{Key: config, Writable: true},
			{Key: epochPDA, Writable: true},
			{Key: Pubkey{}},
		},
		Data: data,
	})
	if err != nil {
		return "", err
	}
	signature, err := p.client.Send(ctx, transaction)
	if err != nil {
		return "", err
	}
	// Выплаты идут сразу за публикацией, а preflight у них считается на
	// finalized. Не дождавшись финализации, каждый клейм отбивается о цепочку,
	// которая про эпоху ещё не знает
	if err := p.awaitFinal(ctx, signature); err != nil {
		return "", err
	}
	if p.log != nil {
		p.log("chain: epoch %d published as %s", epoch.Number, signature)
	}
	return signature, nil
}

// awaitFinal ждёт, пока цепочка признает транзакцию окончательной
func (p *Publisher) awaitFinal(ctx context.Context, signature string) error {
	ticker := time.NewTicker(finalPoll)
	defer ticker.Stop()
	for {
		ok, err := p.client.Confirmed(ctx, signature)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("chain: %s was not finalised in time", signature)
		case <-ticker.C:
		}
	}
}

// finalPoll - как часто спрашиваем цепочку про судьбу транзакции
const finalPoll = 2 * time.Second

// FindPDA считает адрес, который программа выведет у себя. Считаем сами, а не
// храним: захардкоженный адрес однажды разъедется с программой
func FindPDA(program Pubkey, seeds [][]byte) (Pubkey, uint8, error) {
	for bump := 255; bump >= 0; bump-- {
		var buf []byte
		for _, seed := range seeds {
			buf = append(buf, seed...)
		}
		buf = append(buf, byte(bump))
		buf = append(buf, program[:]...)
		buf = append(buf, []byte("ProgramDerivedAddress")...)
		sum := sha256.Sum256(buf)
		// Точка на кривой - законный адрес аккаунта, и PDA такой быть не может
		if !onCurve(sum) {
			return Pubkey(sum), uint8(bump), nil
		}
	}
	return Pubkey{}, 0, fmt.Errorf("chain: no bump found for %x", program[:4])
}

// Client и Signer отдают то, чем публикатор ходит в цепочку: заводить донору
// счёт удобнее тем же ключом и тем же соединением
func (p *Publisher) Client() *Client { return p.client }

func (p *Publisher) Signer() *Signer { return p.signer }

// NextEpoch читает из конфига номер, который программа примет следующим.
//
// Держать счётчик у себя нельзя: цепочка и база разъезжаются при любой
// неудачной публикации, а спорит тут цепочка
func (p *Publisher) NextEpoch(ctx context.Context) (uint64, error) {
	config, _, err := FindPDA(p.program, [][]byte{seedConfig})
	if err != nil {
		return 0, err
	}
	data, err := p.client.AccountData(ctx, config)
	if err != nil {
		return 0, err
	}
	// Раскладка Config: тег, authority, mint, epoch_cap, next_epoch
	if len(data) < 81 {
		return 0, fmt.Errorf("chain: the config is shorter than expected")
	}
	return binary.LittleEndian.Uint64(data[73:81]), nil
}
