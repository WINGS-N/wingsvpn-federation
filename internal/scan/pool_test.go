package scan

import "testing"

func TestPlausibleSNIDropsForeignRegionalNames(t *testing.T) {
	for _, ok := range []string{"www.nvidia.com", "music.yandex.ru", "cdn.samsung.io", "shop.kz"} {
		if !PlausibleSNI(ok) {
			t.Errorf("%s должен был пройти", ok)
		}
	}
	for _, bad := range []string{"blog.nvidia.com.br", "www.nvidia.in", "store.sony.co.jp", "nohost"} {
		if PlausibleSNI(bad) {
			t.Errorf("%s не должен попадать в пул", bad)
		}
	}
}
