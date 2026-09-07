package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"wingsnet.org/federation/internal/head/payout"
)

// PDA обязан сойтись с тем, что выведет программа у себя: разъедется - цепочка
// отобьёт транзакцию, и понять почему будет не по чему
func TestPDAMatchesTheProgram(t *testing.T) {
	raw, err := payout.DecodeBase58("11111111111111111111111111111112")
	if err != nil {
		t.Fatal(err)
	}
	var program Pubkey
	copy(program[:], raw)

	got, bump, err := FindPDA(program, [][]byte{seedConfig})
	if err != nil {
		t.Fatal(err)
	}
	// Адрес не на кривой: иначе у него был бы приватный ключ, и подписывать за
	// него программа не смогла бы
	if onCurve(got) {
		t.Fatal("PDA оказался на кривой")
	}
	if bump == 0 {
		t.Fatal("bump нулевой, так почти не бывает")
	}
	// Тот же вход даёт тот же адрес: иначе публикация каждый раз метит в новый
	// аккаунт
	again, _, err := FindPDA(program, [][]byte{seedConfig})
	if err != nil || again != got {
		t.Fatalf("PDA пляшет от вызова к вызову: %v", err)
	}
}

// Порядок аккаунтов в сообщении не абы какой: сперва подписанты с записью,
// потом остальные. Перепутается - цепочка отвергнет транзакцию
func TestMessageOrdersAccountsByRights(t *testing.T) {
	payer := key(1)
	writable := key(2)
	readonly := key(3)
	program := key(4)

	message, signers, err := BuildMessage(payer, [32]byte{9}, []Instruction{{
		ProgramID: program,
		Accounts: []AccountMeta{
			{Key: readonly},
			{Key: writable, Writable: true},
		},
		Data: []byte{1, 2, 3},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 || signers[0] != payer {
		t.Fatalf("подписант не тот: %v", signers)
	}
	if message[0] != 1 {
		t.Fatalf("подписантов насчитали %d", message[0])
	}
	// Плательщик идёт первым: цепочка списывает комиссию именно с него
	if hex.EncodeToString(message[4:36]) != hex.EncodeToString(payer[:]) {
		t.Fatal("плательщик не первый в списке")
	}
}

// Подпись должна ложиться на то же сообщение, которое уедет в цепочку
func TestSignedTransactionCarriesTheMessage(t *testing.T) {
	public, secret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var payer Pubkey
	copy(payer[:], public)

	message, signers, err := BuildMessage(payer, [32]byte{7}, []Instruction{{
		ProgramID: key(8),
		Accounts:  []AccountMeta{{Key: payer, Signer: true, Writable: true}},
		Data:      []byte{42},
	}})
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := SignTransaction(message, signers, map[Pubkey]ed25519.PrivateKey{payer: secret})
	if err != nil {
		t.Fatal(err)
	}
	// Один подписант: байт длины, 64 байта подписи, дальше сообщение
	if transaction[0] != 1 {
		t.Fatalf("подписей в транзакции %d", transaction[0])
	}
	signature := transaction[1:65]
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("подпись не проверяется")
	}
	if hex.EncodeToString(transaction[65:]) != hex.EncodeToString(message) {
		t.Fatal("в транзакцию уехало не то сообщение")
	}
}

// Ключ не того размера - это не транзакция, а способ подписать хуйню
func TestSignerRefusesAWrongKey(t *testing.T) {
	if _, err := NewSigner(make([]byte, 32)); err == nil {
		t.Fatal("короткий ключ приняли")
	}
}

func key(seed byte) Pubkey {
	var out Pubkey
	out[0] = seed
	out[31] = seed
	return out
}

// Вектор снят с solana CLI: свой вывод PDA обязан сходиться с настоящим, иначе
// транзакции летят в мусор, а причина нащупывается только вручную
func TestPDAAgainstTheRealThing(t *testing.T) {
	raw, err := payout.DecodeBase58("11111111111111111111111111111112")
	if err != nil {
		t.Fatal(err)
	}
	var program Pubkey
	copy(program[:], raw)

	got, _, err := FindPDA(program, [][]byte{[]byte("config")})
	if err != nil {
		t.Fatal(err)
	}
	want, err := payout.DecodeBase58("DKZ5QBBLBCt9yn4PAyYngB91XnkP7KmhVDGTmjgzikSP")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
		t.Fatalf("PDA разъехался с цепочкой:\n наш %x\n её  %x", got[:], want)
	}
}

// Заведение аккаунта требует подписи самого аккаунта, а не только плательщика:
// без чужого ключа цепочка отобьёт транзакцию
func TestSignManyCarriesEveryRequiredSignature(t *testing.T) {
	payerPublic, payerSecret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	freshPublic, freshSecret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var payer, fresh Pubkey
	copy(payer[:], payerPublic)
	copy(fresh[:], freshPublic)

	signer, err := NewSigner(payerSecret)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := signer.SignMany(
		[32]byte{5},
		[]Instruction{{
			ProgramID: key(9),
			Accounts: []AccountMeta{
				{Key: payer, Signer: true, Writable: true},
				{Key: fresh, Signer: true, Writable: true},
			},
			Data: []byte{1},
		}},
		map[Pubkey]ed25519.PrivateKey{fresh: freshSecret},
	)
	if err != nil {
		t.Fatal(err)
	}
	if transaction[0] != 2 {
		t.Fatalf("подписей в транзакции %d, а подписантов двое", transaction[0])
	}
	message := transaction[1+2*64:]
	if !ed25519.Verify(payerPublic, message, transaction[1:65]) {
		t.Fatal("подпись плательщика не проверяется")
	}
	if !ed25519.Verify(freshPublic, message, transaction[65:129]) {
		t.Fatal("подпись нового аккаунта не проверяется")
	}
}

// Без ключа подписанта транзакцию собирать нельзя: молча отдать её в цепочку
// значит получить отказ без внятной причины
func TestSignManyRefusesWithoutAKey(t *testing.T) {
	_, payerSecret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(payerSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignMany([32]byte{1}, []Instruction{{
		ProgramID: key(9),
		Accounts:  []AccountMeta{{Key: key(3), Signer: true, Writable: true}},
	}}, nil); err == nil {
		t.Fatal("собрали транзакцию без ключа подписанта")
	}
}
