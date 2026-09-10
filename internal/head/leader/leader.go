// Package leader держит активной ровно одну башку.
//
// Башка держит стримы всего флота и считает статистику в памяти: две активные
// реплики поделят агентов и разойдутся в цифрах. Лиза делает вторую горячим
// резервом, из-за чего выкат перестаёт быть простоем
package leader

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// Duration - на сколько берётся лиза, renew - как часто держатель её продлевает.
// Резерв ждёт истечения, поэтому разрыв между ними и есть время переключения
const (
	Duration = 15 * time.Second
	renew    = 5 * time.Second
)

// microTime - формат MicroTime в kube-api: он принимает ровно шесть знаков в
// долях секунды, а наносекунды отбивает как Bad Request
const microTime = "2006-01-02T15:04:05.000000Z07:00"

// Kube - тот кусок kube-api, который здесь нужен
type Kube interface {
	Namespace() string
	GetRaw(ctx context.Context, path string) ([]byte, error)
	PutRaw(ctx context.Context, path string, manifest map[string]any) ([]byte, error)
	PostRaw(ctx context.Context, path string, manifest map[string]any) ([]byte, error)
}

// Elector крутит выборы и говорит, кто их выиграл
type Elector struct {
	kube     Kube
	name     string
	identity string
	leader   atomic.Bool
	now      func() time.Time
	// onChange узнаёт о смене роли: пода в резерве надо убрать из Service, а
	// не притворяться неготовым - иначе выкат не досчитается готовых реплик и
	// не завершится никогда
	onChange func(leading bool)
}

// OnChange ставит колбэк. Задаётся один раз при сборке
func (e *Elector) OnChange(fn func(leading bool)) { e.onChange = fn }

// New builds an elector. Identity - имя пода: держатель должен быть узнаваем,
// когда лиза застряла
func New(kube Kube, name, identity string) *Elector {
	return &Elector{kube: kube, name: name, identity: identity, now: time.Now}
}

// lease - лиза, как её отдаёт kube-api
type lease struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity"`
		LeaseDurationSeconds int    `json:"leaseDurationSeconds"`
		RenewTime            string `json:"renewTime"`
		AcquireTime          string `json:"acquireTime"`
	} `json:"spec"`
}

// IsLeader говорит, держит ли этот процесс лизу
func (e *Elector) IsLeader() bool { return e.leader.Load() }

// Run keeps trying until ctx ends. Потеря лизы не убивает процесс: он
// возвращается в резерв и ждёт следующей попытки
func (e *Elector) Run(ctx context.Context) {
	ticker := time.NewTicker(renew)
	defer ticker.Stop()
	for {
		held, err := e.tryAcquire(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("leader: %v", err)
		}
		if held != e.leader.Swap(held) {
			if held {
				log.Printf("leader: %s took the lease", e.identity)
			} else {
				log.Printf("leader: %s lost the lease", e.identity)
			}
			if e.onChange != nil {
				e.onChange(held)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Elector) path() string {
	return fmt.Sprintf("/apis/coordination.k8s.io/v1/namespaces/%s/leases/%s", e.kube.Namespace(), e.name)
}

func (e *Elector) tryAcquire(ctx context.Context) (bool, error) {
	raw, err := e.kube.GetRaw(ctx, e.path())
	if err != nil {
		return false, err
	}
	now := e.now().UTC()
	if raw == nil {
		return e.create(ctx, now)
	}
	var current lease
	if err := json.Unmarshal(raw, &current); err != nil {
		return false, err
	}
	mine := current.Spec.HolderIdentity == e.identity
	if !mine && !expired(current, now) {
		return false, nil
	}
	// resourceVersion в PUT: если другая реплика успела взять лизу между
	// чтением и записью, api откажет вместо того, чтобы дать двух лидеров
	body := map[string]any{
		"apiVersion": "coordination.k8s.io/v1",
		"kind":       "Lease",
		"metadata": map[string]any{
			"name":            e.name,
			"namespace":       e.kube.Namespace(),
			"resourceVersion": current.Metadata.ResourceVersion,
		},
		"spec": map[string]any{
			"holderIdentity":       e.identity,
			"leaseDurationSeconds": int(Duration.Seconds()),
			"renewTime":            now.Format(microTime),
			"acquireTime":          acquireTime(current, mine, now),
		},
	}
	if _, err := e.kube.PutRaw(ctx, e.path(), body); err != nil {
		// Отказ означает, что кто-то успел раньше, и это штатный ход выборов
		return false, nil
	}
	return true, nil
}

func (e *Elector) create(ctx context.Context, now time.Time) (bool, error) {
	body := map[string]any{
		"apiVersion": "coordination.k8s.io/v1",
		"kind":       "Lease",
		"metadata":   map[string]any{"name": e.name, "namespace": e.kube.Namespace()},
		"spec": map[string]any{
			"holderIdentity":       e.identity,
			"leaseDurationSeconds": int(Duration.Seconds()),
			"renewTime":            now.Format(microTime),
			"acquireTime":          now.Format(microTime),
		},
	}
	listPath := fmt.Sprintf("/apis/coordination.k8s.io/v1/namespaces/%s/leases", e.kube.Namespace())
	if _, err := e.kube.PostRaw(ctx, listPath, body); err != nil {
		// Создание лизы проигрывается только гонкой, всё остальное - настоящая
		// поломка, и молчать о ней значит оставить обе реплики в резерве
		return false, err
	}
	return true, nil
}

func expired(l lease, now time.Time) bool {
	renewed, err := time.Parse(microTime, l.Spec.RenewTime)
	if err != nil {
		return true
	}
	window := time.Duration(l.Spec.LeaseDurationSeconds) * time.Second
	if window == 0 {
		window = Duration
	}
	return now.After(renewed.Add(window))
}

func acquireTime(l lease, mine bool, now time.Time) string {
	if mine && l.Spec.AcquireTime != "" {
		return l.Spec.AcquireTime
	}
	return now.Format(microTime)
}

// WhileLeading крутит fn, только пока реплика держит лизу, и останавливает её
// сразу после потери. Резерв, крутящий ротацию и destwatch, менял бы флот
// одновременно с активной башкой
func WhileLeading(ctx context.Context, e *Elector, fn func(context.Context)) {
	if e == nil {
		fn(ctx)
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	stop := func() {}
	defer func() { stop() }()
	running := false
	for {
		switch leading := e.IsLeader(); {
		case leading && !running:
			inner, cancel := context.WithCancel(ctx)
			stop = cancel
			running = true
			go fn(inner)
		case !leading && running:
			stop()
			stop, running = func() {}, false
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
