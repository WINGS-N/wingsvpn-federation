package main

import (
	"crypto/sha512"
	"encoding/binary"
	"time"

	"wingsnet.org/federation/internal/head/destwatch"
	"wingsnet.org/federation/internal/head/fleet"
	"wingsnet.org/federation/internal/head/registry"
)

// rescueFleet сводит вместе зонды, реестр и настройки флота.
//
// Смотреть на dest со стороны башки бесполезно: у неё всё отвечает прекрасно,
// потому что сидит она не там, где юзеры. Разваливается связка dest с подписью,
// и видно это только оттуда, откуда реально ходят
type rescueFleet struct {
	reg   *registry.Registry
	fleet *fleet.Manager
	// republish перерисовывает конфиг и рассылает его флоту. Без этого новый
	// dest лежит в реестре мёртвым грузом, а нода как была тёмной, так и
	// осталась
	republish func()
}

// ProbeHealth отдаёт свежие замеры по нодам
func (f rescueFleet) ProbeHealth(within time.Duration) []destwatch.NodeHealth {
	now := time.Now()
	nodes := f.reg.List()
	out := make([]destwatch.NodeHealth, 0, len(nodes))
	for _, node := range nodes {
		var measured, ok bool
		for _, reach := range node.Reachability {
			if now.Sub(reach.At) > within {
				continue
			}
			measured = true
			if reach.OK {
				ok = true
			}
		}
		// Нода, которую вообще не мерили, не тёмная, а неизвестная. Менять ей
		// dest на этом основании значит дёргать половину флота просто так
		if !measured {
			continue
		}
		out = append(out, destwatch.NodeHealth{NodeID: node.ID, OK: ok, Dest: node.RealityDest})
	}
	return out
}

// PickDest выбирает ноде другую цель из проверенного пула
func (f rescueFleet) PickDest(nodeID, avoid string) (string, bool) {
	settings := f.fleet.Settings()
	pool := settings.DestPool
	if len(pool) < 2 {
		return "", false
	}
	// Идём по пулу от места, выведенного из имени ноды: две тёмные ноды не
	// должны толпой переехать на один и тот же dest
	sum := sha512.Sum512_256([]byte(nodeID + avoid))
	start := int(binary.BigEndian.Uint32(sum[:4]) % uint32(len(pool)))
	for i := 0; i < len(pool); i++ {
		candidate := pool[(start+i)%len(pool)]
		if candidate != avoid {
			return candidate, true
		}
	}
	return "", false
}

// SetDest прибивает ноде новый dest и толкает ей конфиг
func (f rescueFleet) SetDest(nodeID, dest string) error {
	if err := f.reg.SetDest(nodeID, dest); err != nil {
		return err
	}
	if f.republish != nil {
		f.republish()
	}
	return nil
}
