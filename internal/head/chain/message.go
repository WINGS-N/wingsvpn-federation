// Package chain отправляет транзакции Solana.
//
// Библиотеку не тянем: она тащит за собой пол-интернета, а нам нужна ровно одна
// транзакция за эпоху. Формат legacy-сообщения простой, и собрать его руками
// дешевле, чем таскать чужой мир зависимостей
package chain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Pubkey - адрес аккаунта в цепочке
type Pubkey [32]byte

// AccountMeta - как инструкция трогает аккаунт. Порядок и флаги важны: цепочка
// по ним решает, что подписывать и что можно менять
type AccountMeta struct {
	Key      Pubkey
	Signer   bool
	Writable bool
}

// Instruction - что зовём и с какими аккаунтами
type Instruction struct {
	ProgramID Pubkey
	Accounts  []AccountMeta
	Data      []byte
}

// BuildMessage собирает legacy-сообщение.
//
// Аккаунты идут строго по убыванию прав: сперва подписанты с записью, потом
// подписанты только на чтение, потом остальные. Перепутаешь порядок - цепочка
// отвергнет транзакцию, и понять почему будет нечем
func BuildMessage(payer Pubkey, blockhash [32]byte, instructions []Instruction) ([]byte, []Pubkey, error) {
	if len(instructions) == 0 {
		return nil, nil, errors.New("chain: nothing to send")
	}

	type entry struct {
		key      Pubkey
		signer   bool
		writable bool
	}
	order := []entry{{key: payer, signer: true, writable: true}}
	add := func(key Pubkey, signer, writable bool) {
		for i := range order {
			if order[i].key == key {
				order[i].signer = order[i].signer || signer
				order[i].writable = order[i].writable || writable
				return
			}
		}
		order = append(order, entry{key: key, signer: signer, writable: writable})
	}
	for _, in := range instructions {
		for _, meta := range in.Accounts {
			add(meta.Key, meta.Signer, meta.Writable)
		}
		add(in.ProgramID, false, false)
	}

	rank := func(e entry) int {
		switch {
		case e.signer && e.writable:
			return 0
		case e.signer:
			return 1
		case e.writable:
			return 2
		default:
			return 3
		}
	}
	sorted := make([]entry, 0, len(order))
	for group := 0; group < 4; group++ {
		for _, e := range order {
			if rank(e) == group {
				sorted = append(sorted, e)
			}
		}
	}

	var signers, readonlySigners, readonlyOthers uint8
	keys := make([]Pubkey, 0, len(sorted))
	index := map[Pubkey]byte{}
	for i, e := range sorted {
		keys = append(keys, e.key)
		index[e.key] = byte(i)
		if e.signer {
			signers++
			if !e.writable {
				readonlySigners++
			}
		} else if !e.writable {
			readonlyOthers++
		}
	}

	out := []byte{signers, readonlySigners, readonlyOthers}
	out = appendCompact(out, len(keys))
	for _, key := range keys {
		out = append(out, key[:]...)
	}
	out = append(out, blockhash[:]...)
	out = appendCompact(out, len(instructions))
	for _, in := range instructions {
		programIndex, ok := index[in.ProgramID]
		if !ok {
			return nil, nil, fmt.Errorf("chain: program %x is missing", in.ProgramID[:4])
		}
		out = append(out, programIndex)
		out = appendCompact(out, len(in.Accounts))
		for _, meta := range in.Accounts {
			idx, ok := index[meta.Key]
			if !ok {
				return nil, nil, errors.New("chain: an account is missing")
			}
			out = append(out, idx)
		}
		out = appendCompact(out, len(in.Data))
		out = append(out, in.Data...)
	}

	signerKeys := make([]Pubkey, 0, signers)
	for _, e := range sorted {
		if e.signer {
			signerKeys = append(signerKeys, e.key)
		}
	}
	return out, signerKeys, nil
}

// SignTransaction подписывает сообщение и заворачивает в транзакцию
func SignTransaction(message []byte, signerKeys []Pubkey, keys map[Pubkey]ed25519.PrivateKey) ([]byte, error) {
	out := appendCompact(nil, len(signerKeys))
	for _, key := range signerKeys {
		secret, ok := keys[key]
		if !ok {
			return nil, fmt.Errorf("chain: no key for signer %x", key[:4])
		}
		out = append(out, ed25519.Sign(secret, message)...)
	}
	return append(out, message...), nil
}

// appendCompact пишет длину в формате compact-u16, которого ждёт Solana
func appendCompact(dst []byte, value int) []byte {
	for {
		chunk := byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			return append(dst, chunk)
		}
		dst = append(dst, chunk|0x80)
	}
}
