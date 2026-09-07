package tokens

import (
	"errors"
	"strings"
)

// A donor gets one opaque string in the install command, but it carries two
// values: the fleet secret that keys the transport, and the single-use token
// that authorises the join.
//
// Both are needed because tokenaead derives its key from a shared secret, so the
// head cannot try every outstanding token to decrypt an incoming connection. The
// fleet secret is shared among donors and is not an authenticator - it only
// keeps the real token out of a passive observer's reach
const compoundSep = "."

// SplitCompound separates the transport secret from the enroll token
func SplitCompound(value string) (fleetSecret, enrollToken string, err error) {
	idx := strings.LastIndex(value, compoundSep)
	if idx <= 0 || idx == len(value)-1 {
		return "", "", errors.New("tokens: malformed enroll token")
	}
	return value[:idx], value[idx+1:], nil
}

// JoinCompound builds the string handed to a donor
func JoinCompound(fleetSecret, enrollToken string) string {
	return fleetSecret + compoundSep + enrollToken
}
