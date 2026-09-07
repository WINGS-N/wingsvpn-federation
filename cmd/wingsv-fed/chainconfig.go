package main

// Конфиг программы выплат: минт, потолок эпохи и кулдаун вывода залога.
//
// Живёт подкомандой, а не одноразовым скриптом: заводится это раз в жизни сети,
// и через полгода никто нахуй не вспомнит, чем оно делалось

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"time"

	"wingsnet.org/federation/internal/head/chain"
)

const (
	ixInitConfig = 0
	ixSetConfig  = 7
)

// systemProgram - 32 нуля, адрес System Program
var systemProgram chain.Pubkey

func runChainConfig(args []string) error {
	fs := flag.NewFlagSet("chain-config", flag.ContinueOnError)
	rpc := fs.String("rpc", "https://api.devnet.solana.com", "solana rpc endpoint")
	keyPath := fs.String("key", "", "path to the head keypair, it is the program authority")
	programID := fs.String("program", "", "base58 address of the payouts program")
	mintID := fs.String("mint-address", "", "base58 mint the payouts are made in")
	cap := fs.Uint64("epoch-cap", 0, "hard ceiling on one epoch, in token units")
	cooldown := fs.Duration("cooldown", 7*24*time.Hour, "how long an unstake waits")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *programID == "" || *mintID == "" {
		return errors.New("chain-config: -key, -program and -mint-address are required")
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

	client := chain.New(*rpc)
	ctx := context.Background()

	// Первый раз конфиг надо завести, дальше - только править: init по второму
	// разу программа отобьёт, и это правильно, иначе им уводят казну
	data, err := client.AccountData(ctx, config)
	if err != nil && !errors.Is(err, chain.ErrNoAccount) {
		return err
	}
	tag := byte(ixInitConfig)
	accounts := []chain.AccountMeta{
		{Key: signer.Public, Signer: true, Writable: true},
		{Key: config, Writable: true},
		{Key: mint},
		{Key: systemProgram},
	}
	if len(data) > 0 {
		tag = ixSetConfig
		accounts = accounts[:3]
	}

	payload := make([]byte, 17)
	payload[0] = tag
	binary.LittleEndian.PutUint64(payload[1:], *cap)
	binary.LittleEndian.PutUint64(payload[9:], uint64(cooldown.Seconds()))

	blockhash, err := client.LatestBlockhash(ctx)
	if err != nil {
		return err
	}
	transaction, err := signer.Sign(blockhash, chain.Instruction{
		ProgramID: program,
		Accounts:  accounts,
		Data:      payload,
	})
	if err != nil {
		return err
	}
	signature, err := client.Send(ctx, transaction)
	if err != nil {
		return err
	}
	fmt.Println("config:  ", chain.Base58(config))
	fmt.Println("mint:    ", chain.Base58(mint))
	if tag == ixInitConfig {
		fmt.Println("config created")
	} else {
		fmt.Println("config updated")
	}
	return confirm(ctx, client, signature)
}
