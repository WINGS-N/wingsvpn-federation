package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"

	headpb "wingsnet.org/federation/gen/headpb"
	"wingsnet.org/federation/internal/common/tokenaead"
)

// runMint asks a running head for an enroll token.
//
// The panel is the ordinary way to get one, but an operator holding the head's
// panel secret should not need a browser session to bring up a node - and during
// a bootstrap there is no admin account to log in with yet.
func runMint(args []string) error {
	fs := newFlagSet("mint")
	head := fs.String("head", "127.0.0.1:9311", "the head's panel-facing endpoint")
	secret := fs.String("secret", "", "the head's panel secret, never the fleet secret")
	donor := fs.String("donor", "owner", "who the nodes are donated by")
	uses := fs.Uint("uses", 1, "how many nodes may join on this one token")
	ttl := fs.Duration("ttl", time.Hour, "how long the token stays valid")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*secret) == "" {
		return errors.New("-secret is required")
	}

	conn, err := grpc.NewClient(*head, grpc.WithTransportCredentials(tokenaead.Client(*secret)))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := headpb.NewFederationHeadClient(conn).MintEnrollToken(ctx, &headpb.MintEnrollTokenRequest{
		DonorId:    *donor,
		TtlSeconds: uint32(ttl.Seconds()),
		Uses:       uint32(*uses),
	})
	if err != nil {
		return err
	}
	if cmd := resp.GetInstallCommand(); cmd != "" {
		_, _ = fmt.Fprintln(fs.Output(), "install:", cmd)
	}
	// The token alone on stdout, so this composes with a pipe
	fmt.Println(resp.GetEnrollToken())
	return nil
}
