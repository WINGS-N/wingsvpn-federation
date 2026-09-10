package nodetrust

import "time"

// Как только платят строго за байты, появляется смысл гонять трафик самому себе:
// завёл пару приглашённых, качаешь через свою же ноду и выписываешь себе деньги.
//
// Судим двумя способами. Точный - по дереву инвайтов, которое присылает панель:
// доля трафика ноды, приходящая от людей из поддерева её же донора. Грубый - по
// концентрации, когда дерева нет: у честной ноды трафик размазан, а у фермы
// весь объём висит на паре подписей

// selfDealHeads - сколько самых жирных клиентов складываем. Двое, потому что
// заводить десяток подставных ради выплаты уже дороже самой выплаты
const selfDealHeads = 2

// selfDealShare - доля этих двоих, за которой начинается разговор
const selfDealShare = 0.9

// selfDealMinBytes - ниже этого объёма концентрация не значит нихуя: на новой
// или почти пустой ноде один живой человек законно даёт все сто процентов
const selfDealMinBytes = 50 << 30

// ownTrafficShare - доля своих же приглашённых, за которой начинается разговор.
// Не сто процентов нарочно: донор вправе пользоваться своей нодой сам, и пара
// его людей на ней это нормальная жизнь, а не ферма
const ownTrafficShare = 0.75

// ClientMix - сколько байт подписал каждый субъект на одной ноде
type ClientMix interface {
	SignedByNodeAndSubject(start, end time.Time) (map[string]map[string]uint64, error)
}

// DonorOf говорит, чья это нода
type DonorOf interface {
	DonorOfNode(nodeID string) (string, bool)
}

// ownShare - какая доля трафика ноды пришла от людей из поддерева её донора
func ownShare(clients map[string]uint64, donorID string, tree Ancestry) (share float64, total uint64) {
	var own uint64
	for subject, bytes := range clients {
		total += bytes
		if subject == donorID {
			own += bytes
			continue
		}
		for _, ancestor := range tree.Ancestors(subject) {
			if ancestor == donorID {
				own += bytes
				break
			}
		}
	}
	if total == 0 {
		return 0, 0
	}
	return float64(own) / float64(total), total
}

// concentration отдаёт долю самых жирных клиентов и общий объём
func concentration(mix map[string]uint64) (share float64, total uint64) {
	if len(mix) == 0 {
		return 0, 0
	}
	top := make([]uint64, 0, len(mix))
	for _, bytes := range mix {
		total += bytes
		top = append(top, bytes)
	}
	// Хватает частичной сортировки: нужны только самые жирные, а не весь порядок
	var heads uint64
	for i := 0; i < selfDealHeads && len(top) > 0; i++ {
		best, at := uint64(0), 0
		for j, bytes := range top {
			if bytes > best {
				best, at = bytes, j
			}
		}
		heads += best
		top = append(top[:at], top[at+1:]...)
	}
	if total == 0 {
		return 0, 0
	}
	return float64(heads) / float64(total), total
}

// WatchInviteTree подключает карту приглашений
func (a *Auditor) WatchInviteTree(tree Ancestry, donors DonorOf) {
	a.tree, a.donors = tree, donors
}

// JudgeSelfDealing смотрит, не обслуживает ли нода саму себя
func (a *Auditor) JudgeSelfDealing(mix ClientMix) {
	if mix == nil {
		return
	}
	end := a.now()
	byNode, err := mix.SignedByNodeAndSubject(end.Add(-auditWindow), end)
	if err != nil {
		if a.log != nil {
			a.log("nodetrust: client mix unreadable: %v", err)
		}
		return
	}
	for address, clients := range byNode {
		nodeID := address
		if a.resolve != nil {
			if resolved, ok := a.resolve.NodeByAddress(address); ok {
				nodeID = resolved
			}
		}
		// Дерево точнее концентрации и потому старше: оно отличает ноду с
		// парой живых людей от ноды, возящей своих же приглашённых
		if a.tree != nil && a.tree.Known() && a.donors != nil {
			donorID, ok := a.donors.DonorOfNode(nodeID)
			if ok {
				share, total := ownShare(clients, donorID, a.tree)
				if total >= selfDealMinBytes && share >= ownTrafficShare {
					a.accuseSelfDealing(nodeID, share, ownTrafficShare, end,
						"%s carries %.0f%% of its traffic for its own invitees")
				}
				continue
			}
		}
		share, total := concentration(clients)
		if total < selfDealMinBytes || share < selfDealShare {
			continue
		}
		a.accuseSelfDealing(nodeID, share, selfDealShare, end,
			"%s carries %.0f%% of its traffic for a couple of clients")
	}
}

// accuseSelfDealing выписывает обвинение. Величина - насколько перебрали порог:
// нода, где всё до последнего байта своё, хуже пограничной
func (a *Auditor) accuseSelfDealing(nodeID string, share, threshold float64, at time.Time, format string) {
	magnitude := (share - threshold) * 100
	if magnitude < 1 {
		magnitude = 1
	}
	a.judge.Observe(Claim{
		NodeID: nodeID, Reason: ReasonSelfDealing,
		Magnitude: magnitude, At: at,
	})
	if a.log != nil {
		a.log("nodetrust: "+format, nodeID, share*100)
	}
}
