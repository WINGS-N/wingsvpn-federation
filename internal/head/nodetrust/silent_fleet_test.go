package nodetrust

import (
	"testing"
	"time"
)

type staticClaimed map[string]uint64

func (s staticClaimed) NodeTraffic(time.Time) (map[string]uint64, error) {
	return map[string]uint64(s), nil
}

type staticSigned map[string]uint64

func (s staticSigned) SignedByNode(time.Time) (map[string]uint64, error) {
	return map[string]uint64(s), nil
}

type sameNode struct{}

func (sameNode) NodeByAddress(address string) (string, bool) { return address, true }

// Молчит весь флот - молчим и мы: сломалась наша сторона, а не все доноры
// сговорились врать в одну минуту
func TestМолчащийФлотНеШтрафуется(t *testing.T) {
	judge := NewJudge()
	audit := NewAuditor(
		staticClaimed{"node-1": 4 << 30},
		staticSigned{},
		sameNode{}, judge, nil,
	)

	// Первый круг только запоминает предысторию, штрафы считаются со второго
	audit.Once()
	audit.Once()

	if verdict := judge.Judge("node-1"); verdict.Trust != 100 {
		t.Fatalf("нода на молчащем флоте получила штраф: доверие %d", verdict.Trust)
	}
}
