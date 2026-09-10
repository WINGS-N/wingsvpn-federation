package probes

import (
	"testing"
	"time"

	fedpb "wingsnet.org/federation/gen/fedpb"
	"wingsnet.org/federation/internal/head/profiles"
)

// Сверка при переподключении перезаписывает профиль зонда, и если она отдаст
// его с пометкой учёта, наши замеры лягут донору в счёт как его трафик
func TestПрофильЗондаНеСчитаетсяТрафикомДонора(t *testing.T) {
	fleet := &Fleet{
		byNode: map[string]profiles.Profile{},
		config: func(string) *fedpb.NodeConfig {
			return &fedpb.NodeConfig{Inbounds: []*fedpb.InboundSpec{{Tag: "tcp"}}}
		},
	}
	profile, err := profiles.Issue("probe", "node-1", time.Now(), 0)
	if err != nil {
		t.Fatalf("профиль не выписался: %v", err)
	}
	fleet.byNode["node-1"] = profile

	for _, spec := range fleet.SpecsFor("node-1") {
		if spec.GetMetered() {
			t.Fatal("сверка вернула профиль зонда как оплачиваемый")
		}
	}
}
