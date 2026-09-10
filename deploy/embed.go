// Package deploy carries what a donated machine needs to join.
//
// The installer is embedded rather than fetched from a repository so a node
// always gets the script that matches the head it is joining
package deploy

import (
	_ "embed"
	"strings"
)

//go:embed join.sh
var joinScript string

// JoinScript renders the installer for one head.
//
// head is the gRPC endpoint the agent will dial; release is where the agent
// binary lives, with __ARCH__ where the architecture goes. Both are substituted
// here so the donor pastes one command and nothing else has to be explained
func JoinScript(head, release string) string {
	out := strings.ReplaceAll(joinScript, "__WINGSV_HEAD__", head)
	return strings.ReplaceAll(out, "__WINGSV_RELEASE__", release)
}
