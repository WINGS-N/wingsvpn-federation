package chain

import "filippo.io/edwards25519"

// onCurve говорит, лежит ли точка на ed25519.
//
// PDA обязан быть НЕ на кривой: точка на кривой это законный адрес аккаунта, у
// которого есть приватный ключ, и программа таким адресом подписывать не может
func onCurve(candidate [32]byte) bool {
	_, err := new(edwards25519.Point).SetBytes(candidate[:])
	return err == nil
}
