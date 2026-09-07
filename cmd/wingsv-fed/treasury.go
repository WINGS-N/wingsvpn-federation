package main

// Казна выплат: завести токен, налить в неё и открыть донору счёт.
//
// Живёт в нашем бинаре, а не гоняется чужим spl-token: тот не собирается на
// свежих крейтах, тянет полчаса компиляции и всё равно умеет ровно то же самое

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"wingsnet.org/federation/internal/head/chain"
)

// waitFinal - сколько ждём финализации. Публичный RPC умеет тупить, но не
// бесконечно
const waitFinal = 90 * time.Second

func runTreasury(args []string) error {
	fs := flag.NewFlagSet("treasury", flag.ContinueOnError)
	rpc := fs.String("rpc", "https://api.devnet.solana.com", "solana rpc endpoint")
	keyPath := fs.String("key", "", "path to the keypair that pays and mints")
	programID := fs.String("program", "", "base58 address of the payouts program")
	decimals := fs.Uint("decimals", 6, "token decimals, USDT uses 6")
	amount := fs.Uint64("mint", 0, "how much to mint into the treasury right away")
	openFor := fs.String("open-for", "", "base58 wallet to open a token account for")
	mintID := fs.String("mint-address", "", "existing mint, needed with -open-for")
	fund := fs.Uint64("fund", 0, "top the treasury up by this much, in the token's smallest units")
	mintInto := fs.String("mint-into", "", "mint -mint units into this token account, needs the mint authority")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("treasury: -key is required")
	}
	signer, err := loadChainKey(*keyPath)
	if err != nil {
		return err
	}
	client := chain.New(*rpc)
	ctx := context.Background()

	// Счёт донору: минт уже есть, заводим только адрес, куда придут деньги
	if *openFor != "" {
		if *mintID == "" {
			return errors.New("treasury: -open-for needs -mint-address")
		}
		account, signature, err := client.OpenAccount(ctx, signer,
			chain.MustKey(*mintID), chain.MustKey(*openFor))
		if err != nil {
			return err
		}
		fmt.Println("account:", chain.Base58(account))
		return confirm(ctx, client, signature)
	}

	if *programID == "" {
		return errors.New("treasury: -program is required, the vault sits under its pda")
	}
	program := chain.MustKey(*programID)
	owner, _, err := chain.FindPDA(program, [][]byte{[]byte("treasury")})
	if err != nil {
		return err
	}

	// Чеканка на готовый счёт. На чужом минте вроде USDT не сработает и не
	// должна: там мы никто, а вот на своём тестовом это единственный способ
	// раздать токены
	if *mintInto != "" {
		if *mintID == "" || *fund == 0 {
			return errors.New("treasury: -mint-into needs -mint-address and -fund")
		}
		blockhash, err := client.LatestBlockhash(ctx)
		if err != nil {
			return err
		}
		transaction, err := signer.Sign(blockhash, chain.MintTo(
			chain.MustKey(*mintID), chain.MustKey(*mintInto), signer.Public, *fund))
		if err != nil {
			return err
		}
		signature, err := client.Send(ctx, transaction)
		if err != nil {
			return err
		}
		fmt.Println("account:", *mintInto)
		return confirm(ctx, client, signature)
	}

	// Пополнение казны. Идёт мимо программы обычным переводом токенов, поэтому
	// удержать с него нечего: комиссия живёт в инструкции, а тут её нет
	if *fund > 0 {
		if *mintID == "" {
			return errors.New("treasury: -fund needs -mint-address")
		}
		mint := chain.MustKey(*mintID)
		from, err := client.TokenAccountOf(ctx, signer.Public, mint)
		if err != nil {
			return fmt.Errorf("treasury: %s has no account on this mint: %w",
				chain.Base58(signer.Public), err)
		}
		to, err := client.TokenAccountOf(ctx, owner, mint)
		if err != nil {
			return fmt.Errorf("treasury: the vault is not open on this mint: %w", err)
		}
		blockhash, err := client.LatestBlockhash(ctx)
		if err != nil {
			return err
		}
		transaction, err := signer.Sign(blockhash, chain.Transfer(from, to, signer.Public, *fund))
		if err != nil {
			return err
		}
		signature, err := client.Send(ctx, transaction)
		if err != nil {
			return err
		}
		fmt.Println("from:    ", chain.Base58(from))
		fmt.Println("treasury:", chain.Base58(to))
		return confirm(ctx, client, signature)
	}

	// Минт уже есть - значит платим чужим токеном вроде USDT, и заводить свой
	// нахуй не надо: казна это просто счёт на нём под нашим PDA
	if *mintID != "" {
		account, signature, err := client.OpenAccount(ctx, signer, chain.MustKey(*mintID), owner)
		if err != nil {
			return err
		}
		fmt.Println("mint:    ", *mintID)
		fmt.Println("treasury:", chain.Base58(account))
		fmt.Println("owner:   ", chain.Base58(owner))
		return confirm(ctx, client, signature)
	}
	treasury, signature, err := client.CreateTreasury(ctx, signer, owner, uint8(*decimals), *amount)
	if err != nil {
		return err
	}
	fmt.Println("mint:    ", chain.Base58(treasury.Mint))
	fmt.Println("treasury:", chain.Base58(treasury.Account))
	fmt.Println("owner:   ", chain.Base58(treasury.Owner))
	return confirm(ctx, client, signature)
}

func confirm(ctx context.Context, client *chain.Client, signature string) error {
	deadline := time.Now().Add(waitFinal)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		ok, err := client.Confirmed(ctx, signature)
		if err != nil {
			return err
		}
		if ok {
			fmt.Println("done:    ", signature)
			return nil
		}
	}
	return fmt.Errorf("treasury: %s did not finalize", signature)
}

func loadChainKey(path string) (*chain.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var numbers []byte
	if err := json.Unmarshal(raw, &numbers); err != nil {
		return nil, fmt.Errorf("keypair does not parse: %w", err)
	}
	return chain.NewSigner(numbers)
}
