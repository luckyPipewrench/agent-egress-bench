package fixture

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
)

// WSFixture runs a WebSocket echo server for testing frame-level DLP scanning.
// Pipelock's /ws proxy relays frames through this server; the proxy scans
// each frame for DLP patterns and blocks matching traffic.
type WSFixture struct {
	listener net.Listener
	server   *http.Server
}

// Addr returns the listener address (host:port).
func (f *WSFixture) Addr() string {
	return f.listener.Addr().String()
}

// WSURL returns the full WebSocket URL for connecting.
func (f *WSFixture) WSURL() string {
	return fmt.Sprintf("ws://%s/echo", f.listener.Addr().String())
}

// StartWS creates and starts a WebSocket echo server on a random port.
func StartWS() (*WSFixture, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/echo", websocket.Handler(func(ws *websocket.Conn) {
		// Echo all frames back to sender.
		_, _ = io.Copy(ws, ws)
	}))
	// Health check for readiness.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	})

	f := &WSFixture{
		listener: ln,
		server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}

	go func() { _ = f.server.Serve(ln) }()
	return f, nil
}

// Close stops the WebSocket server.
func (f *WSFixture) Close() {
	_ = f.server.Close()
}
