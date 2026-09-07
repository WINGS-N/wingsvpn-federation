package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// envPrefix namespaces the variables so a shared docker-compose file cannot
// collide with something else on the host
const envPrefix = "WINGSV_FED_"

// applyEnvDefaults fills flags the caller left unset from the environment, so a
// container can be configured entirely by env and never needs a command line.
// The name maps mechanically: -grpc-listen reads WINGSV_FED_GRPC_LISTEN.
//
// Flags win over the environment, and only flags the caller did not pass are
// touched - an explicit empty value stays empty. A secret passed this way also
// stays out of the process table, which an argument does not.
func applyEnvDefaults(fs *flag.FlagSet) error {
	passed := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { passed[f.Name] = true })

	var failed error
	fs.VisitAll(func(f *flag.Flag) {
		if failed != nil || passed[f.Name] {
			return
		}
		key := envPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		value, ok := os.LookupEnv(key)
		if !ok {
			return
		}
		if err := fs.Set(f.Name, value); err != nil {
			failed = fmt.Errorf("%s: %w", key, err)
		}
	})
	return failed
}

// parseFlags is Parse plus the environment fallback. Every subcommand goes
// through it so the env contract is the same everywhere.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	return applyEnvDefaults(fs)
}
