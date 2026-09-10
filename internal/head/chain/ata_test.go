package chain

import "testing"

// Ассоциированный счёт обязан совпадать с тем, что считают кошельки и биржи:
// свой аккаунт вместо него означает деньги там, куда человек не смотрит
func TestАссоциированныйСчётСходитсяСКошельком(t *testing.T) {
	owner := MustKey("D7jqCxX6huU3tQJGTLSNPMx3sR4op4fbeq689rwm9A7g")
	mint := MustKey("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB")

	got, err := AssociatedAccount(owner, mint)
	if err != nil {
		t.Fatalf("счёт не вывелся: %v", err)
	}
	// Живой счёт этого кошелька, тот самый, где лежат деньги
	const want = "HiCskM9j2Wvcuqje26QutCddkJDWTkU4DbYoAVDV1F5s"
	if Base58(got) != want {
		t.Fatalf("вывели %s, а кошелёк шлёт на %s", Base58(got), want)
	}
}
