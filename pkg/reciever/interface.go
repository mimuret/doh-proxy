package reciever

import (
	"context"
	"net"
)

type Reciever interface {
	StartServer(serverName string, listeners []net.Listener)
	Shutdown(ctx context.Context) error
}
