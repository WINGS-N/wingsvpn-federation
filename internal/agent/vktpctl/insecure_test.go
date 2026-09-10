package vktpctl

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// insecureCreds keeps the tests off tokenaead: the transport is not what is
// under test here
type insecureCreds struct{}

func (insecureCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, info{}, nil
}

func (insecureCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, info{}, nil
}

func (insecureCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "insecure"}
}

func (insecureCreds) Clone() credentials.TransportCredentials { return insecureCreds{} }

func (insecureCreds) OverrideServerName(string) error { return nil }

type info struct{}

func (info) AuthType() string { return "insecure" }
