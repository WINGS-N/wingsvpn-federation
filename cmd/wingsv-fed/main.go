// Command wingsv-fed is the single federation binary. The subcommand picks the
// role: agent on a donated node, head next to the panel, probe on a vantage
// point inside the censored network, enroll for one-shot joining.
//
// One binary and one path on disk, deliberately. The panel's connect.sh carries
// a whole marker-string workaround because a shell wrapper on PATH swallowed
// unknown subcommands and exited zero, so a failed setup reported success. Here
// the exit code is the contract
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is stamped from the git tag at build time. It stays a var because a
// const cannot be set by the linker, and it stays empty so an unstamped build
// reports honestly rather than claiming a release number that has gone stale
var version string

func usage() {
	fmt.Fprint(os.Stderr, `wingsv-fed - WINGS V federation

Usage:
  wingsv-fed head    [flags]   run the federation head next to the panel
  wingsv-fed agent   [flags]   run on a donated node
  wingsv-fed probe   [flags]   run on a vantage point inside the censored network
  wingsv-fed enroll  [flags]   join the federation once, then exit
  wingsv-fed mint    [flags]   ask a head for an enroll token
  wingsv-fed scan    [flags]   find dests a node can borrow a tls identity from
  wingsv-fed treasury [flags]  set up the payout token, its treasury and donor accounts
  wingsv-fed chain-config [flags]  set the payout mint, epoch cap and unstake cooldown
  wingsv-fed fee     [flags]   set the operator cut, open its account or withdraw it
  wingsv-fed donate  [flags]   pay into the treasury through the program, cut included
  wingsv-fed train   [flags]   train the oracle model on what the head collected
  wingsv-fed doctor            print what this machine looks like to the head
  wingsv-fed version

`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "head":
		err = runHead(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "probe":
		err = runProbe(os.Args[2:])
	case "enroll":
		err = runEnroll(os.Args[2:])
	case "mint":
		err = runMint(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "treasury":
		err = runTreasury(os.Args[2:])
	case "chain-config":
		err = runChainConfig(os.Args[2:])
	case "fee":
		err = runFee(os.Args[2:])
	case "donate":
		err = runDonate(os.Args[2:])
	case "train":
		runTrain(os.Args[2:])
	case "doctor":
		err = runDoctor(os.Args[2:])
	case "version":
		fmt.Println(resolveVersion())
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	return "0.0.0-dev"
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
