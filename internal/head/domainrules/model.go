package domainrules

import (
	"context"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/boost"
	"wingsnet.org/federation/internal/head/features"
)

// Recorder копит векторы для будущего обучения.
//
// Метка кладётся сразу: когда обвинение выписали правила, спрашивать про этот
// же вектор модель незачем и опасно. Она на пограничных случаях плавает, ответит
// "чисто" - и бустинг выучит, что десяток TLS-стеков на одной ссылке это норма.
// Минус единица означает "не знаем", и вот такие уже уходят на разметку
type Recorder interface {
	PutSnapshot(subjectID string, at time.Time, version string, values map[string]float64, label int16, by string) error
}

// LabelByRules - чем подписана разметка от правил
const LabelByRules = "rules"

// LabelUnknown - метки нет, вектор ждёт разметчика
const LabelUnknown = -1

// SetRecorder включает накопление. Без него модель учить будет не на чем
func (l *Loop) SetRecorder(r Recorder) { l.recorder = r }

// modelScorer гоняет обученный бустинг по вектору
type modelScorer struct {
	model *boost.Model
	// threshold - с какой вероятности модель открывает рот. Высокий нарочно:
	// сомневающаяся модель должна молчать, а не портить человеку жизнь
	threshold float64
}

// NewModelScorer оборачивает обученную модель в скорер
func NewModelScorer(model *boost.Model) VectorScorer {
	return &modelScorer{model: model, threshold: 0.8}
}

func (m *modelScorer) Name() string { return "boost/" + m.model.Version() }

func (m *modelScorer) ScoreVector(_ context.Context, v features.Vector) ([]features.Finding, error) {
	score := m.model.Score(v.Values())
	if score < m.threshold {
		return nil, nil
	}
	return []features.Finding{{
		// Класс общий: модель говорит "тут что-то не то", а какой именно вид
		// злоупотребления - это работа правил, у них на то есть основания
		Kind:  fedpb.AbuseKind_ABUSE_KIND_HIGH_FANOUT,
		Count: uint32(score * 100),
		Why:   "модель считает поведение непохожим на живого человека",
	}}, nil
}
