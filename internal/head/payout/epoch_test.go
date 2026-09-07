package payout

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// wallets - настоящие base58-адреса по 32 байта, потому что сборка эпохи их
// декодирует и на выдуманной строке просто откажется работать
var wallets = []string{
	"11111111111111111111111111111112",
	"So11111111111111111111111111111111111111112",
	"Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
	"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
	"SysvarRent111111111111111111111111111111111",
}

func epochWindow() (time.Time, time.Time) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return start, start.Add(7 * 24 * time.Hour)
}

// Пруф каждого листа обязан сойтись с корнем, иначе донор придёт в цепочку и
// уйдёт ни с чем
func TestEveryLeafProves(t *testing.T) {
	start, end := epochWindow()
	leaves := make([]Leaf, 0, len(wallets))
	for i, w := range wallets {
		leaves = append(leaves, Leaf{Address: w, Amount: Micro(1_000_000 * (i + 1))})
	}
	epoch, err := BuildEpoch(7, start, end, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if epoch.Total != Micro(15_000_000) {
		t.Fatalf("сумма эпохи %s, а начислили 15 USDT", epoch.Total.FormatUSDT())
	}
	for _, leaf := range epoch.Leaves {
		proof, err := epoch.Proof(leaf.Address)
		if err != nil {
			t.Fatal(err)
		}
		index, _ := epoch.IndexOf(leaf.Address)
		hash, err := LeafHash(epoch.Number, index, leaf)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyProof(epoch.Root, hash, proof) {
			t.Fatalf("пруф для %s не сошёлся с корнем", leaf.Address)
		}
	}
}

// Нечётное число листьев - тот самый случай, где кривое дерево разваливается
func TestOddLeafCountStillProves(t *testing.T) {
	start, end := epochWindow()
	for _, count := range []int{1, 2, 3, 5} {
		leaves := make([]Leaf, 0, count)
		for i := 0; i < count; i++ {
			leaves = append(leaves, Leaf{Address: wallets[i], Amount: Micro(500_000)})
		}
		epoch, err := BuildEpoch(1, start, end, leaves)
		if err != nil {
			t.Fatalf("%d листьев: %v", count, err)
		}
		for _, leaf := range epoch.Leaves {
			proof, _ := epoch.Proof(leaf.Address)
			index, _ := epoch.IndexOf(leaf.Address)
			hash, _ := LeafHash(epoch.Number, index, leaf)
			if !VerifyProof(epoch.Root, hash, proof) {
				t.Fatalf("%d листьев: пруф для %s не сошёлся", count, leaf.Address)
			}
		}
	}
}

// Приписать себе лишнего не выйдет: сумма входит в лист, а лист в корень
func TestInflatedAmountBreaksProof(t *testing.T) {
	start, end := epochWindow()
	epoch, err := BuildEpoch(3, start, end, []Leaf{
		{Address: wallets[0], Amount: Micro(2_000_000)},
		{Address: wallets[1], Amount: Micro(3_000_000)},
		{Address: wallets[2], Amount: Micro(4_000_000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := epoch.Proof(wallets[0])
	greedy, _ := LeafHash(epoch.Number, 0, Leaf{Address: wallets[0], Amount: Micro(9_000_000)})
	if VerifyProof(epoch.Root, greedy, proof) {
		t.Fatal("завышенная сумма прошла проверку")
	}
}

// Чужой пруф к своему листу не подходит, иначе один донор обнесёт всю эпоху
func TestProofOfAnotherLeafIsUseless(t *testing.T) {
	start, end := epochWindow()
	epoch, err := BuildEpoch(4, start, end, []Leaf{
		{Address: wallets[0], Amount: Micro(1_000_000)},
		{Address: wallets[1], Amount: Micro(1_000_000)},
		{Address: wallets[2], Amount: Micro(1_000_000)},
		{Address: wallets[3], Amount: Micro(1_000_000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	stolen, _ := epoch.Proof(wallets[1])
	mine, _ := LeafHash(epoch.Number, 0, Leaf{Address: wallets[0], Amount: Micro(1_000_000)})
	if VerifyProof(epoch.Root, mine, stolen) {
		t.Fatal("чужой пруф подошёл к своему листу")
	}
}

// Тот же лист из соседней эпохи клеймить нельзя: номер эпохи вшит в хеш
func TestLeafFromAnotherEpochDoesNotProve(t *testing.T) {
	start, end := epochWindow()
	leaves := []Leaf{
		{Address: wallets[0], Amount: Micro(1_000_000)},
		{Address: wallets[1], Amount: Micro(2_000_000)},
	}
	first, err := BuildEpoch(1, start, end, leaves)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildEpoch(2, end, end.Add(time.Hour), leaves)
	if err != nil {
		t.Fatal(err)
	}
	if first.Root == second.Root {
		t.Fatal("две эпохи с одинаковыми листьями дали один корень")
	}
	proof, _ := second.Proof(wallets[0])
	hash, _ := LeafHash(2, 0, Leaf{Address: wallets[0], Amount: Micro(1_000_000)})
	if VerifyProof(first.Root, hash, proof) {
		t.Fatal("лист второй эпохи склеймился по корню первой")
	}
}

// Лист и узел обязаны считаться по-разному, иначе внутренний узел предъявляют
// как лист и клеймят несуществующее начисление
func TestNodeAndLeafLiveInDifferentSpaces(t *testing.T) {
	a, err := LeafHash(1, 0, Leaf{Address: wallets[0], Amount: Micro(1_000_000)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := LeafHash(1, 0, Leaf{Address: wallets[1], Amount: Micro(1_000_000)})
	if err != nil {
		t.Fatal(err)
	}

	node := pairHash(a, b)
	body := make([]byte, 0, 65)
	body = append(body, 0x01)
	if bytesLess(a, b) {
		body = append(body, a[:]...)
		body = append(body, b[:]...)
	} else {
		body = append(body, b[:]...)
		body = append(body, a[:]...)
	}
	if node != sha256.Sum256(body) {
		t.Fatal("узел считается не по задокументированному формату")
	}

	// Тот же материал без тега узла обязан дать другой хеш: на этом и держится
	// невозможность выдать узел за лист
	if node == sha256.Sum256(body[1:]) {
		t.Fatal("тег узла ни на что не влияет")
	}

	// Пара склеивается по возрастанию, поэтому порядок аргументов не важен
	if pairHash(a, b) != pairHash(b, a) {
		t.Fatal("порядок пары меняет хеш, хотя пара сортированная")
	}
}

func bytesLess(a, b [32]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return true
}

// Один донор с двумя нодами получает ОДИН лист: два листа это две законные
// заявки на клейм
func TestDuplicateAddressesAreFolded(t *testing.T) {
	start, end := epochWindow()
	epoch, err := BuildEpoch(6, start, end, []Leaf{
		{Address: wallets[0], Amount: Micro(1_500_000)},
		{Address: wallets[0], Amount: Micro(2_500_000)},
		{Address: wallets[1], Amount: Micro(1_000_000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(epoch.Leaves) != 2 {
		t.Fatalf("листьев %d, а адресов два", len(epoch.Leaves))
	}
	amount, ok := epoch.Amount(wallets[0])
	if !ok || amount != Micro(4_000_000) {
		t.Fatalf("склеенная сумма %s, а начисляли 4 USDT", amount.FormatUSDT())
	}
}

// Порядок, в котором начисления пришли, на корень влиять не должен
func TestRootIsIndependentOfInputOrder(t *testing.T) {
	start, end := epochWindow()
	forward := []Leaf{
		{Address: wallets[0], Amount: Micro(1_000_000)},
		{Address: wallets[1], Amount: Micro(2_000_000)},
		{Address: wallets[2], Amount: Micro(3_000_000)},
	}
	backward := []Leaf{forward[2], forward[0], forward[1]}
	a, err := BuildEpoch(9, start, end, forward)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildEpoch(9, start, end, backward)
	if err != nil {
		t.Fatal(err)
	}
	if a.Root != b.Root {
		t.Fatal("корень зависит от порядка, в котором пришли начисления")
	}
}

// Пустая эпоха и мусорный адрес должны отбиваться на сборке, а не в цепочке
func TestEpochRefusesGarbage(t *testing.T) {
	start, end := epochWindow()
	if _, err := BuildEpoch(1, start, end, nil); err != ErrEmptyEpoch {
		t.Fatalf("пустая эпоха собралась: %v", err)
	}
	if _, err := BuildEpoch(1, start, end, []Leaf{{Address: wallets[0], Amount: 0}}); err != ErrEmptyEpoch {
		t.Fatalf("эпоха из нулевых начислений собралась: %v", err)
	}
	if _, err := BuildEpoch(1, start, end, []Leaf{{Address: "0OIl-не-base58", Amount: Micro(1)}}); err == nil {
		t.Fatal("мусорный адрес прошёл в эпоху")
	}
	epoch, err := BuildEpoch(1, start, end, []Leaf{{Address: wallets[0], Amount: Micro(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := epoch.Proof(wallets[3]); err != ErrNotInEpoch {
		t.Fatalf("пруф выдался тому, кого в эпохе нет: %v", err)
	}
}

// Формат листа читает и программа в цепочке, поэтому он проверяется побайтово,
// а не "как получится"
func TestLeafHashIsTheDocumentedBytes(t *testing.T) {
	leaf := Leaf{Address: wallets[1], Amount: Micro(1_234_567)}
	address, err := base58Decode(leaf.Address)
	if err != nil {
		t.Fatal(err)
	}
	// Тег, индекс листа, адрес, сумма, номер эпохи - ровно в этом порядке
	want := make([]byte, 0, 53)
	want = append(want, 0x00)
	want = binary.LittleEndian.AppendUint32(want, 3)
	want = append(want, address...)
	want = binary.LittleEndian.AppendUint64(want, 1_234_567)
	want = binary.LittleEndian.AppendUint64(want, 42)
	expected := sha256.Sum256(want)

	got, err := LeafHash(42, 3, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatal("хеш листа разъехался с задокументированным форматом")
	}
}

// Пруф, собранный башкой, обязан сходиться с корнем: по нему донор и клеймит, а
// разъехавшийся пруф это деньги, которые нельзя забрать
func TestProofVerifiesAgainstTheRoot(t *testing.T) {
	epoch, err := BuildEpoch(7, time.Now(), time.Now().Add(time.Hour), []Leaf{
		{Address: "11111111111111111111111111111112", Amount: 1_000_000},
		{Address: "So11111111111111111111111111111111111111112", Amount: 2_500_000},
		{Address: "SysvarC1ock11111111111111111111111111111111", Amount: 300},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range epoch.Leaves {
		proof, err := epoch.Proof(leaf.Address)
		if err != nil {
			t.Fatalf("пруф для %s не собрался: %v", leaf.Address, err)
		}
		index, _ := epoch.IndexOf(leaf.Address)
		hash, err := LeafHash(epoch.Number, index, leaf)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyProof(epoch.Root, hash, proof) {
			t.Fatalf("пруф для %s не сходится с корнем", leaf.Address)
		}
		// Та же выплата в соседней эпохе не проходит: номер зашит в лист
		other, err := LeafHash(epoch.Number+1, index, leaf)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyProof(epoch.Root, other, proof) {
			t.Fatalf("лист соседней эпохи прошёл для %s", leaf.Address)
		}
	}
}
