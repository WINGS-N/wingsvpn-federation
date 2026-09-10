package main

import (
	"fmt"
	"os"

	"wingsnet.org/federation/internal/agent/passport"
	"wingsnet.org/federation/internal/agent/state"
	"wingsnet.org/federation/pkg/nodeid"
)

// printDoctor shows what this machine looks like to the head, so support does
// not have to guess why a node was refused
func printDoctor() error {
	p := passport.Collect(resolveVersion())
	fmt.Printf("version:      %s\n", resolveVersion())
	fmt.Printf("fingerprint:  %s\n", nodeid.Fingerprint(""))
	fmt.Printf("hostname:     %s\n", p.GetHostname())
	fmt.Printf("os/arch:      %s/%s kernel %s\n", p.GetOs(), p.GetArch(), p.GetKernel())
	fmt.Printf("cpu/mem:      %d cores, %d MiB\n", p.GetCpuCores(), p.GetMemBytes()>>20)
	fmt.Printf("root:         %v\n", p.GetHasRoot())
	fmt.Printf("kernel wg:    %v\n", p.GetKernelWgAvailable())
	fmt.Printf("aes-ni:       %v\n", p.GetAesNi())

	var v4, v6 int
	for _, addr := range p.GetAddresses() {
		if addr.GetIpv6() {
			v6++
		} else {
			v4++
		}
		fmt.Printf("address:      %s (%s)\n", addr.GetAddress(), addr.GetSource())
	}
	// A node with no IPv4 cannot serve most users, whatever else is healthy
	if v4 == 0 {
		fmt.Printf("WARNING:      no routable IPv4 found; IPv6 alone will not reach most users\n")
	}

	st, err := state.Load(state.DefaultPath)
	switch {
	case err == nil:
		fmt.Printf("enrolled:     yes, node %s via %s\n", st.NodeID, st.HeadEndpoint)
	case os.IsNotExist(err) || err == state.ErrNotEnrolled:
		fmt.Printf("enrolled:     no\n")
	default:
		fmt.Printf("enrolled:     unreadable, %v\n", err)
	}
	return nil
}
