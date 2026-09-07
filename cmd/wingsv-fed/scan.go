package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"wingsnet.org/federation/internal/agent/binfetch"
	"wingsnet.org/federation/internal/scan"
)

// runScan decides which hosts a node may borrow a TLS identity from.
//
// The TLS check alone is not enough to answer that, so this also completes real
// REALITY handshakes when an xray binary is available. Without one it reports the
// TLS verdict and says plainly that nothing was verified
func runScan(args []string) error {
	fs := newFlagSet("scan")
	targets := fs.String("targets", "", "comma-separated dests to scan; empty scans the default pool")
	russianOnly := fs.Bool("ru", false, "scan only the Russian pool")
	binDir := fs.String("bin-dir", "/usr/local/wings/federation/bin", "where the xray binary lives")
	workDir := fs.String("work-dir", os.TempDir(), "scratch space for the verification configs")
	expand := fs.Bool("expand", false, "also scan every name the verified certificates cover")
	verify := fs.Bool("verify", true, "complete a real REALITY handshake per candidate")
	concurrency := fs.Int("concurrency", 8, "parallel TLS probes")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	list := scan.DefaultPool()
	switch {
	case strings.TrimSpace(*targets) != "":
		list = splitList(*targets)
	case *russianOnly:
		list = scan.RussianPool
	}

	ctx := context.Background()
	results := scan.ProbeAll(ctx, list, *concurrency, scan.DefaultTimeout)

	if *expand {
		if extra := scan.ExpandSANs(results); len(extra) > 0 {
			results = append(results, scan.ProbeAll(ctx, extra, *concurrency, scan.DefaultTimeout)...)
		}
	}

	var verifier *scan.Verifier
	if *verify {
		fetcher := binfetch.New(*binDir)
		xrayPath, ok := fetcher.Installed("xray")
		if !ok {
			return errors.New("no xray binary in -bin-dir; pass -verify=false for the tls verdict alone")
		}
		verifier = scan.NewVerifier(xrayPath, *workDir)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TARGET\tTLS\tREALITY\tML-DSA-65\tRTT\tBYTES\tSANS\tNOTE")
	for _, r := range results {
		if verifier != nil && r.Feasible {
			if err := verifier.Verify(ctx, r); err != nil {
				r.Error = err.Error()
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%dms\t%d\t%d\t%s\n",
			r.Target, yesNo(r.Feasible), verdict(r.Feasible, verifier != nil, r.RealityOK),
			verdict(r.RealityOK, verifier != nil, r.PostQuantumOK),
			r.LatencyMs, r.HandshakeBytes, len(r.ServerNames), r.Error)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if best := scan.Best(results); best != nil {
		fmt.Printf("\nbest: -reality-dest %s", best.Target)
		if best.PostQuantumOK {
			fmt.Print(" -reality-pq")
		}
		fmt.Println()
	}
	return nil
}

// verdict distinguishes "no" from "not asked", because reporting an unverified
// dest as failing would send an operator hunting a problem that is not there
func verdict(tested, verifying, ok bool) string {
	if !verifying || !tested {
		return "-"
	}
	return yesNo(ok)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func splitList(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
