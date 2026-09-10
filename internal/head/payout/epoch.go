package payout

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Эпоха это пачка начислений, закрытая одним корнем. Башка пихает в цепочку
// один корень вместо сотни переводов, а донор приходит за своим сам и сам платит
// за свою транзакцию.
//
// Хеш тут SHA-256, и это ЕДИНСТВЕННОЕ место, где мы отступаем от проектного
// SHA-512/256. Причина внешняя: в Solana syscall есть только на sha256, а
// SHA-512 программа считала бы софтом и жрала тысячи compute units на каждый
// уровень дерева. Второго прообраза тут бояться нечего, длины фиксированные, а
// теги листа и узла разведены. Не "чинить" обратно, не разобравшись.
//
// Формат листа прибит намертво, потому что ровно то же самое считает программа в
// цепочке: разъедется хоть на байт - пруфы не сойдутся, и деньги повиснут нахуй

// leafTag и nodeTag разводят лист и узел по разным пространствам. Без них хитрый
// хуй предъявит внутренний узел как лист и склеймит то, чего ему не начисляли
const (
	leafTag byte = 0x00
	nodeTag byte = 0x01
)

var (
	// ErrEmptyEpoch - закрывать эпоху, в которой никому нихуя не причитается,
	// незачем: корень-то будет, а клеймить по нему нечего
	ErrEmptyEpoch = errors.New("payout: epoch has no accruals")
	// ErrNotInEpoch - у этого адреса в эпохе нет листа
	ErrNotInEpoch = errors.New("payout: address is not in this epoch")
)

// Leaf - одна строка начисления, ровно то, что донор заберёт клеймом
type Leaf struct {
	Address string
	Amount  Micro
}

// Epoch - закрытая пачка начислений
type Epoch struct {
	Number uint64
	Start  time.Time
	End    time.Time
	// Leaves отсортированы по адресу: порядок задаёт дерево, и от него зависит
	// корень, поэтому он не может быть тем, в котором листья пришли
	Leaves []Leaf
	Total  Micro
	Root   [32]byte
	// levels держит дерево целиком ради пруфов. Уровень 0 это хеши листьев
	levels [][][32]byte
}

// RootHex отдаёт корень строкой, в таком виде он и уезжает в цепочку
func (e *Epoch) RootHex() string { return hex.EncodeToString(e.Root[:]) }

// BuildEpoch сводит начисления в дерево.
//
// Одинаковые адреса складываются, а не идут двумя листьями: два листа на один
// адрес это две законные заявки на клейм, и донор с чистой совестью заберёт обе
func BuildEpoch(number uint64, start, end time.Time, leaves []Leaf) (*Epoch, error) {
	folded := map[string]Micro{}
	for _, leaf := range leaves {
		if leaf.Amount == 0 {
			continue
		}
		if err := ValidateSolanaAddress(leaf.Address); err != nil {
			return nil, err
		}
		folded[leaf.Address] += leaf.Amount
	}
	if len(folded) == 0 {
		return nil, ErrEmptyEpoch
	}

	epoch := &Epoch{Number: number, Start: start, End: end, Leaves: make([]Leaf, 0, len(folded))}
	for address, amount := range folded {
		epoch.Leaves = append(epoch.Leaves, Leaf{Address: address, Amount: amount})
		epoch.Total += amount
	}
	sort.Slice(epoch.Leaves, func(i, j int) bool { return epoch.Leaves[i].Address < epoch.Leaves[j].Address })

	hashes := make([][32]byte, 0, len(epoch.Leaves))
	for index, leaf := range epoch.Leaves {
		h, err := LeafHash(number, uint32(index), leaf)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	epoch.levels = buildLevels(hashes)
	epoch.Root = epoch.levels[len(epoch.levels)-1][0]
	return epoch, nil
}

// LeafHash считает хеш листа. Адрес идёт сырыми 32 байтами, а не строкой: в
// цепочке он тоже байты, и тащить туда base58 это лишний код на ровном месте.
//
// Индекс - номер листа в дереве. Он нужен цепочке, чтобы отметка о выплате была
// битом в самой эпохе, а не отдельным аккаунтом за ренту на каждого донора
func LeafHash(epoch uint64, index uint32, leaf Leaf) ([32]byte, error) {
	address, err := base58Decode(leaf.Address)
	if err != nil {
		return [32]byte{}, err
	}
	if len(address) != 32 {
		return [32]byte{}, fmt.Errorf("payout: address decodes to %d bytes, want 32", len(address))
	}
	buf := make([]byte, 0, 1+4+32+8+8)
	buf = append(buf, leafTag)
	buf = binary.LittleEndian.AppendUint32(buf, index)
	buf = append(buf, address...)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(leaf.Amount))
	buf = binary.LittleEndian.AppendUint64(buf, epoch)
	return sha256.Sum256(buf), nil
}

// buildLevels поднимает дерево снизу вверх. Нечётный хвост едет наверх как есть,
// а дублировать его нельзя нахуй: тогда одинокий лист прикидывается парой
func buildLevels(leaves [][32]byte) [][][32]byte {
	levels := [][][32]byte{leaves}
	current := leaves
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 == len(current) {
				next = append(next, current[i])
				continue
			}
			next = append(next, pairHash(current[i], current[i+1]))
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// pairHash склеивает пару по возрастанию. Отсортированная пара избавляет пруф от
// бита "я слева или справа", а проверку в цепочке от лишней ветки и лишних CU
func pairHash(a, b [32]byte) [32]byte {
	buf := make([]byte, 0, 1+64)
	buf = append(buf, nodeTag)
	if bytes.Compare(a[:], b[:]) <= 0 {
		buf = append(buf, a[:]...)
		buf = append(buf, b[:]...)
	} else {
		buf = append(buf, b[:]...)
		buf = append(buf, a[:]...)
	}
	return sha256.Sum256(buf)
}

// Proof собирает путь от листа донора к корню
func (e *Epoch) Proof(address string) ([][32]byte, error) {
	index := -1
	for i, leaf := range e.Leaves {
		if leaf.Address == address {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, ErrNotInEpoch
	}
	proof := make([][32]byte, 0, len(e.levels))
	for _, level := range e.levels[:len(e.levels)-1] {
		sibling := index ^ 1
		if sibling < len(level) {
			proof = append(proof, level[sibling])
		}
		index /= 2
	}
	return proof, nil
}

// Amount отдаёт начисленное адресу в этой эпохе
func (e *Epoch) Amount(address string) (Micro, bool) {
	for _, leaf := range e.Leaves {
		if leaf.Address == address {
			return leaf.Amount, true
		}
	}
	return 0, false
}

// VerifyProof повторяет то, что делает программа в цепочке. Своя проверка нужна,
// чтобы кривой пруф ловился тут, а не еблом донора об отклонённый клейм
func VerifyProof(root [32]byte, leafHash [32]byte, proof [][32]byte) bool {
	computed := leafHash
	for _, sibling := range proof {
		computed = pairHash(computed, sibling)
	}
	return computed == root
}

// IndexOf - номер листа донора в дереве. Цепочка отмечает выплату битом по
// этому номеру, поэтому он едет вместе с пруфом
func (e *Epoch) IndexOf(address string) (uint32, bool) {
	for i, leaf := range e.Leaves {
		if leaf.Address == address {
			return uint32(i), true
		}
	}
	return 0, false
}
