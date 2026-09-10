// Package addrhash считает отпечаток адреса.
//
// Башке для сверки нужен не сам адрес, а только ответ на вопрос "тот же самый
// или нет". Отпечаток отвечает на него и при этом не носит наверх ничего, что
// можно было бы прочитать
package addrhash

import (
	"crypto/sha512"
	"net"
	"strings"
)

// Size - сколько байт отпечатка везём. Восьми хватает: подобрать под них другой
// адрес из четырёх миллиардов возможных нельзя, а места они не занимают
const Size = 8

// Of считает отпечаток адреса, отрезая порт
func Of(addr string) []byte {
	host := strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return nil
	}
	// Нормализуем запись: один и тот же адрес бывает записан по-разному, а
	// отпечатки от разных записей не сойдутся никогда
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	sum := sha512.Sum512_256([]byte("wingsv-fed-addr-v1\x00" + host))
	return sum[:Size]
}

// Matches говорит, есть ли отпечаток адреса среди присланных
func Matches(addr string, hashes [][]byte) bool {
	want := Of(addr)
	if want == nil {
		return false
	}
	for _, got := range hashes {
		if len(got) == len(want) && string(got) == string(want) {
			return true
		}
	}
	return false
}
