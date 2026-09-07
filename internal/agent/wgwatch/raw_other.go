//go:build !linux

package wgwatch

import "errors"

// Сырой сокет есть только на Linux, ноды крутятся там. Сборка под всё
// остальное нужна лишь для тестов и разработки
func openRaw(string) (PacketSource, error) {
	return nil, errors.New("wgwatch: the raw socket is linux only")
}
