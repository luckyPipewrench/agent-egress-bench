package fixture

import (
	"fmt"
	"net"
)

const (
	trustedLoopback       = "127.0.0.1"
	untrustedSinkLoopback = "127.0.0.2"
)

func listenLoopbackPair() (net.Listener, net.Listener, error) {
	primary, err := net.Listen("tcp", trustedLoopback+":0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", trustedLoopback, err)
	}
	_, port, err := net.SplitHostPort(primary.Addr().String())
	if err != nil {
		_ = primary.Close()
		return nil, nil, fmt.Errorf("split primary listener address: %w", err)
	}
	secondary, err := net.Listen("tcp", net.JoinHostPort(untrustedSinkLoopback, port))
	if err != nil {
		_ = primary.Close()
		return nil, nil, fmt.Errorf("listen %s:%s: %w", untrustedSinkLoopback, port, err)
	}
	return primary, secondary, nil
}
