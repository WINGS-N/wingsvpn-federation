package nodetrust

import "sync"

// Дерево инвайтов живёт в панели: у башки нет ни аккаунтов, ни того, кто кого
// позвал. Панель присылает карту сама, и без неё самообслуживание судится
// только по концентрации, то есть заметно грубее

// Ancestry говорит, в чьём поддереве сидит участник
type Ancestry interface {
	// Ancestors - все доноры вверх по цепочке, включая пригласившего напрямую
	Ancestors(subjectID string) []string
	// Known - пришла ли карта вообще. Пустое дерево и отсутствующее это разные
	// вещи: по первому судить можно, по второму нельзя
	Known() bool
}

// Tree держит присланную панелью карту
type Tree struct {
	mu        sync.RWMutex
	ancestors map[string][]string
	loaded    bool
}

func NewTree() *Tree { return &Tree{ancestors: map[string][]string{}} }

// Replace кладёт свежую карту целиком. Именно целиком: инвайт могли отозвать, а
// доклеивание к старой карте оставило бы связь, которой больше нет
func (t *Tree) Replace(ancestors map[string][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ancestors = ancestors
	t.loaded = true
}

func (t *Tree) Ancestors(subjectID string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ancestors[subjectID]
}

func (t *Tree) Known() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.loaded
}

// Size - сколько участников в карте
func (t *Tree) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ancestors)
}
