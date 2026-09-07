package main

// Комиссия оператора: ставка, счёт под неё, вывод накопленного и донат юзера.
//
// Спонсорский взнос сюда не заходит: тот кладётся прямым переводом токенов и
// программу не зовёт вовсе, поэтому удерживать с него нечего и негде

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"

	"wingsnet.org/federation/internal/head/chain"
)

const (
	ixSetFee      = 8
	ixDonate      = 9
	ixWithdrawFee = 10
)

func runFee(args []string) error {
	fs := flag.NewFlagSet("fee", flag.ContinueOnError)
	rpc := fs.String("rpc", "https://api.devnet.solana.com", "solana rpc endpoint")
	keyPath := fs.String("key", "", "path to the head keypair, it is the program authority")
	programID := fs.String("program", "", "base58 address of the payouts program")
	mintID := fs.String("mint-address", "", "base58 mint the payouts are made in")
	setBps := fs.Int("set-bps", -1, "operator cut in basis points, 250 is 2.5 percent")
	open := fs.Bool("open", false, "open the token account the cut lands on")
	withdraw := fs.Uint64("withdraw", 0, "move this much out of the fee account")
	to := fs.String("to", "", "token account the withdrawal goes to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *programID == "" {
		return errors.New("fee: -key and -program are required")
	}
	signer, err := loadChainKey(*keyPath)
	if err != nil {
		return err
	}
	program := chain.MustKey(*programID)
	config, _, err := chain.FindPDA(program, [][]byte{[]byte("config")})
	if err != nil {
		return err
	}
	feeState, _, err := chain.FindPDA(program, [][]byte{[]byte("fee")})
	if err != nil {
		return err
	}
	client := chain.New(*rpc)
	ctx := context.Background()

	// Счёт комиссии живёт под тем же PDA, что и её ставка: адрес выводится из
	// программы, а не хранится где-то ещё
	if *open {
		if *mintID == "" {
			return errors.New("fee: -open needs -mint-address")
		}
		account, signature, err := client.OpenAccount(ctx, signer, chain.MustKey(*mintID), feeState)
		if err != nil {
			return err
		}
		fmt.Println("fee account:", chain.Base58(account))
		fmt.Println("owner:      ", chain.Base58(feeState))
		return confirm(ctx, client, signature)
	}

	if *withdraw > 0 {
		if *to == "" || *mintID == "" {
			return errors.New("fee: -withdraw needs -to and -mint-address")
		}
		from, err := client.TokenAccountOf(ctx, feeState, chain.MustKey(*mintID))
		if err != nil {
			return fmt.Errorf("fee: the fee account is not open: %w", err)
		}
		payload := make([]byte, 9)
		payload[0] = ixWithdrawFee
		binary.LittleEndian.PutUint64(payload[1:], *withdraw)
		signature, err := send(ctx, client, signer, chain.Instruction{
			ProgramID: program,
			Accounts: []chain.AccountMeta{
				{Key: signer.Public, Signer: true, Writable: true},
				{Key: config},
				{Key: feeState},
				{Key: from, Writable: true},
				{Key: chain.MustKey(*to), Writable: true},
				{Key: chain.TokenProgram},
			},
			Data: payload,
		})
		if err != nil {
			return err
		}
		fmt.Println("from:", chain.Base58(from))
		fmt.Println("to:  ", *to)
		return confirm(ctx, client, signature)
	}

	if *setBps < 0 {
		return errors.New("fee: pick one of -set-bps, -open or -withdraw")
	}
	if *setBps > 3000 {
		return errors.New("fee: the program refuses anything above 3000 bps")
	}
	payload := make([]byte, 3)
	payload[0] = ixSetFee
	binary.LittleEndian.PutUint16(payload[1:], uint16(*setBps))
	signature, err := send(ctx, client, signer, chain.Instruction{
		ProgramID: program,
		Accounts: []chain.AccountMeta{
			{Key: signer.Public, Signer: true, Writable: true},
			{Key: config, Writable: true},
			{Key: feeState, Writable: true},
			{Key: chain.Pubkey{}},
		},
		Data: payload,
	})
	if err != nil {
		return err
	}
	fmt.Println("fee state:", chain.Base58(feeState))
	fmt.Printf("cut:       %d bps\n", *setBps)
	return confirm(ctx, client, signature)
}

// runDonate платит через программу, поэтому с суммы удерживается комиссия.
//
// Пополнение казны напрямую делает treasury -fund: тот перевод программу не
// зовёт, и комиссии на нём нет
func runDonate(args []string) error {
	fs := flag.NewFlagSet("donate", flag.ContinueOnError)
	rpc := fs.String("rpc", "https://api.devnet.solana.com", "solana rpc endpoint")
	keyPath := fs.String("key", "", "path to the keypair the tokens are taken from")
	programID := fs.String("program", "", "base58 address of the payouts program")
	mintID := fs.String("mint-address", "", "base58 mint of the donation")
	amount := fs.Uint64("amount", 0, "how much to donate, in the token's smallest units")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *programID == "" || *mintID == "" || *amount == 0 {
		return errors.New("donate: -key, -program, -mint-address and -amount are required")
	}
	signer, err := loadChainKey(*keyPath)
	if err != nil {
		return err
	}
	program := chain.MustKey(*programID)
	mint := chain.MustKey(*mintID)
	config, _, err := chain.FindPDA(program, [][]byte{[]byte("config")})
	if err != nil {
		return err
	}
	feeState, _, err := chain.FindPDA(program, [][]byte{[]byte("fee")})
	if err != nil {
		return err
	}
	treasuryOwner, _, err := chain.FindPDA(program, [][]byte{[]byte("treasury")})
	if err != nil {
		return err
	}

	client := chain.New(*rpc)
	ctx := context.Background()
	from, err := client.TokenAccountOf(ctx, signer.Public, mint)
	if err != nil {
		return fmt.Errorf("donate: %s has no account on this mint: %w", chain.Base58(signer.Public), err)
	}
	treasury, err := client.TokenAccountOf(ctx, treasuryOwner, mint)
	if err != nil {
		return fmt.Errorf("donate: the vault is not open on this mint: %w", err)
	}
	feeAccount, err := client.TokenAccountOf(ctx, feeState, mint)
	if err != nil {
		return fmt.Errorf("donate: the fee account is not open: %w", err)
	}

	payload := make([]byte, 9)
	payload[0] = ixDonate
	binary.LittleEndian.PutUint64(payload[1:], *amount)
	signature, err := send(ctx, client, signer, chain.Instruction{
		ProgramID: program,
		Accounts: []chain.AccountMeta{
			{Key: signer.Public, Signer: true, Writable: true},
			{Key: config},
			{Key: feeState},
			{Key: from, Writable: true},
			{Key: treasury, Writable: true},
			{Key: feeAccount, Writable: true},
			{Key: chain.TokenProgram},
		},
		Data: payload,
	})
	if err != nil {
		return err
	}
	fmt.Println("from:    ", chain.Base58(from))
	fmt.Println("treasury:", chain.Base58(treasury))
	fmt.Println("fee:     ", chain.Base58(feeAccount))
	return confirm(ctx, client, signature)
}

// send подписывает одну инструкцию и отправляет её
func send(
	ctx context.Context,
	client *chain.Client,
	signer *chain.Signer,
	instruction chain.Instruction,
) (string, error) {
	blockhash, err := client.LatestBlockhash(ctx)
	if err != nil {
		return "", err
	}
	transaction, err := signer.Sign(blockhash, instruction)
	if err != nil {
		return "", err
	}
	return client.Send(ctx, transaction)
}
