// Package boost - градиентный бустинг на решающих деревьях, свой и целиком в Go.
//
// Инференс это обход дерева, то бишь вложенные if, поэтому модель молотит прямо
// в башке и стоит микросекунды. Ни питона, ни видеокарты, ни похода наружу
package boost

import (
	"bytes"
	"math"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	modelpb "wingsnet.org/federation/gen/modelpb"
)

// Model - обученный ансамбль
type Model struct {
	pb *modelpb.BoostModel
}

// FromProto оборачивает разобранную модель
func FromProto(pb *modelpb.BoostModel) *Model { return &Model{pb: pb} }

// Proto отдаёт модель как есть
func (m *Model) Proto() *modelpb.BoostModel { return m.pb }

// Version - какая именно модель вынесла вердикт
func (m *Model) Version() string { return m.pb.GetVersion() }

// TrainedOn - на скольких примерах училась
func (m *Model) TrainedOn() int { return int(m.pb.GetTrainedOn()) }

// Score отдаёт вероятность того, что перед нами злоупотребление
func (m *Model) Score(values map[string]float64) float64 {
	features := m.pb.GetFeatures()
	x := make([]float64, len(features))
	for i, name := range features {
		x[i] = values[name]
	}
	raw := m.pb.GetBase()
	for _, tree := range m.pb.GetTrees() {
		raw += m.pb.GetRate() * predict(tree, x)
	}
	return sigmoid(raw)
}

// Importance говорит, сколько раз каждый признак решал судьбу. Грубо, зато сразу
// видно, по чему эта штука вообще судит
func (m *Model) Importance() map[string]int {
	out := map[string]int{}
	features := m.pb.GetFeatures()
	for _, tree := range m.pb.GetTrees() {
		for _, n := range tree.GetNodes() {
			if f := int(n.GetFeature()); f >= 0 && f < len(features) {
				out[features[f]]++
			}
		}
	}
	return out
}

func predict(tree *modelpb.Tree, x []float64) float64 {
	nodes := tree.GetNodes()
	if len(nodes) == 0 {
		return 0
	}
	i := 0
	for {
		n := nodes[i]
		f := int(n.GetFeature())
		if f < 0 || f >= len(x) {
			return n.GetValue()
		}
		if x[f] <= n.GetThreshold() {
			i = int(n.GetLeft())
		} else {
			i = int(n.GetRight())
		}
		if i < 0 || i >= len(nodes) {
			return n.GetValue()
		}
	}
}

// Encode сжимает модель. Ансамбль это сотни почти одинаковых деревьев, поэтому
// zstd срезает его в разы, а разжимается эта хуйня один раз при загрузке
func (m *Model) Encode() ([]byte, error) {
	raw, err := proto.Marshal(m.pb)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode поднимает модель из сжатого протобуфа
func Decode(data []byte) (*Model, error) {
	reader, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := reader.DecodeAll(data, nil)
	if err != nil {
		return nil, err
	}
	var pb modelpb.BoostModel
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, err
	}
	return &Model{pb: &pb}, nil
}

// Params - настройки обучения
type Params struct {
	Rounds       int
	Rate         float64
	MaxDepth     int
	MinChild     int
	Lambda       float64
	MinGain      float64
	MinTrainRows int
}

// DefaultParams - разумное начало для маленькой выборки. Деревья мелкие
// нарочно: на паре тысяч примеров глубокое дерево тупо вызубрит их наизусть и
// на живых данных обосрётся
func DefaultParams() Params {
	return Params{
		Rounds: 120, Rate: 0.1, MaxDepth: 4,
		MinChild: 12, Lambda: 1, MinGain: 0.0, MinTrainRows: 100,
	}
}

// Version - схема модели. Дёргается, когда меняется смысл признаков: иначе
// старая модель будет судить по новым числам и никто этого не заметит
const Version = "boost-v1"

// Sample - одна размеченная строка
type Sample struct {
	Values map[string]float64
	// Label - единица, когда это признанное злоупотребление
	Label float64
}

// ErrNotEnough - учить не на чем
type ErrNotEnough struct{ Rows, Need int }

func (e ErrNotEnough) Error() string {
	return "boost: not enough labelled rows"
}

// Train учит ансамбль. Классика: на каждом круге дерево подгоняется под
// градиент логистической ошибки, то есть под то, где предыдущие ошиблись
func Train(features []string, samples []Sample, p Params) (*Model, error) {
	if len(samples) < p.MinTrainRows {
		return nil, ErrNotEnough{Rows: len(samples), Need: p.MinTrainRows}
	}
	rows := make([][]float64, len(samples))
	y := make([]float64, len(samples))
	for i, s := range samples {
		row := make([]float64, len(features))
		for j, name := range features {
			row[j] = s.Values[name]
		}
		rows[i] = row
		y[i] = s.Label
	}

	positives := 0.0
	for _, label := range y {
		positives += label
	}
	// База это логит доли нарушителей. Модель стартует с честного среднего, а
	// не с нуля, иначе первые деревья просираются на угадывание базовой частоты
	rate := positives / float64(len(y))
	rate = clamp(rate, 1e-6, 1-1e-6)
	base := math.Log(rate / (1 - rate))

	pb := &modelpb.BoostModel{
		Features: features, Base: base, Rate: p.Rate,
		TrainedOn: int32(len(samples)), TrainedAtUnix: time.Now().UTC().Unix(),
		Version: Version,
	}
	raw := make([]float64, len(y))
	for i := range raw {
		raw[i] = base
	}
	grad := make([]float64, len(y))
	hess := make([]float64, len(y))

	for round := 0; round < p.Rounds; round++ {
		for i := range y {
			pred := sigmoid(raw[i])
			grad[i] = pred - y[i]
			hess[i] = pred * (1 - pred)
		}
		tree := growTree(rows, grad, hess, p)
		if len(tree.GetNodes()) == 0 {
			break
		}
		pb.Trees = append(pb.Trees, tree)
		for i := range raw {
			raw[i] += p.Rate * predict(tree, rows[i])
		}
	}
	return &Model{pb: pb}, nil
}

// growTree растит одно дерево жадно, по лучшему приросту
func growTree(rows [][]float64, grad, hess []float64, p Params) *modelpb.Tree {
	tree := &modelpb.Tree{}
	index := make([]int, len(rows))
	for i := range index {
		index[i] = i
	}
	tree.Nodes = append(tree.Nodes, &modelpb.TreeNode{Feature: -1})
	buildNode(tree, 0, index, rows, grad, hess, p, 0)
	return tree
}

func buildNode(tree *modelpb.Tree, at int, index []int, rows [][]float64, grad, hess []float64, p Params, depth int) {
	g, h := sums(index, grad, hess)
	tree.Nodes[at] = &modelpb.TreeNode{Feature: -1, Value: leafValue(g, h, p.Lambda)}
	if depth >= p.MaxDepth || len(index) < 2*p.MinChild {
		return
	}
	feature, threshold, gain, left, right := bestSplit(index, rows, grad, hess, p)
	if feature < 0 || gain <= p.MinGain {
		return
	}
	leftIdx := len(tree.Nodes)
	tree.Nodes = append(tree.Nodes, &modelpb.TreeNode{Feature: -1})
	rightIdx := len(tree.Nodes)
	tree.Nodes = append(tree.Nodes, &modelpb.TreeNode{Feature: -1})
	tree.Nodes[at] = &modelpb.TreeNode{
		Feature: int32(feature), Threshold: threshold,
		Left: int32(leftIdx), Right: int32(rightIdx),
	}
	buildNode(tree, leftIdx, left, rows, grad, hess, p, depth+1)
	buildNode(tree, rightIdx, right, rows, grad, hess, p, depth+1)
}

// bestSplit перебирает признаки и пороги, считая прирост по той же формуле, что
// у взрослых реализаций: сумма квадратов градиента, делённая на гессиан
func bestSplit(index []int, rows [][]float64, grad, hess []float64, p Params) (int, float64, float64, []int, []int) {
	totalG, totalH := sums(index, grad, hess)
	parent := score(totalG, totalH, p.Lambda)

	bestFeature, bestThreshold, bestGain := -1, 0.0, 0.0
	var bestLeft, bestRight []int

	featureCount := 0
	if len(rows) > 0 {
		featureCount = len(rows[0])
	}
	sorted := make([]int, len(index))
	for f := 0; f < featureCount; f++ {
		copy(sorted, index)
		sort.Slice(sorted, func(a, b int) bool { return rows[sorted[a]][f] < rows[sorted[b]][f] })

		leftG, leftH := 0.0, 0.0
		for i := 0; i < len(sorted)-1; i++ {
			leftG += grad[sorted[i]]
			leftH += hess[sorted[i]]
			if i+1 < p.MinChild || len(sorted)-i-1 < p.MinChild {
				continue
			}
			// Порог ставится только между разными значениями, иначе одинаковые
			// строки разъезжаются по разным веткам и дерево учит хуйню
			if rows[sorted[i]][f] == rows[sorted[i+1]][f] {
				continue
			}
			rightG, rightH := totalG-leftG, totalH-leftH
			gain := score(leftG, leftH, p.Lambda) + score(rightG, rightH, p.Lambda) - parent
			if gain > bestGain {
				bestGain = gain
				bestFeature = f
				bestThreshold = (rows[sorted[i]][f] + rows[sorted[i+1]][f]) / 2
				bestLeft = append([]int(nil), sorted[:i+1]...)
				bestRight = append([]int(nil), sorted[i+1:]...)
			}
		}
	}
	return bestFeature, bestThreshold, bestGain, bestLeft, bestRight
}

func sums(index []int, grad, hess []float64) (float64, float64) {
	g, h := 0.0, 0.0
	for _, i := range index {
		g += grad[i]
		h += hess[i]
	}
	return g, h
}

func score(g, h, lambda float64) float64 { return (g * g) / (h + lambda) }

func leafValue(g, h, lambda float64) float64 { return -g / (h + lambda) }

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
