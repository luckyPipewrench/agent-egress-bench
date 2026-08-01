package fixture

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

// WSFixture runs a WebSocket echo server for testing frame-level DLP scanning.
// Pipelock's /ws proxy relays frames through this server; the proxy scans
// each frame for DLP patterns and blocks matching traffic.
type WSFixture struct {
	listener          net.Listener
	untrustedListener net.Listener
	server            *http.Server
	untrustedServer   *http.Server
	messages          atomic.Int64
}

type wsFixtureMessage struct {
	payload     []byte
	payloadType byte
}

var wsFixtureCodec = websocket.Codec{
	Marshal: func(v interface{}) ([]byte, byte, error) {
		msg, ok := v.(wsFixtureMessage)
		if !ok {
			return nil, websocket.UnknownFrame, fmt.Errorf("unsupported websocket fixture message type %T", v)
		}
		return msg.payload, msg.payloadType, nil
	},
	Unmarshal: func(data []byte, payloadType byte, v interface{}) error {
		msg, ok := v.(*wsFixtureMessage)
		if !ok {
			return fmt.Errorf("unsupported websocket fixture receive target %T", v)
		}
		msg.payload = append(msg.payload[:0], data...)
		msg.payloadType = payloadType
		return nil
	},
}

// Addr returns the listener address (host:port).
func (f *WSFixture) Addr() string {
	return f.listener.Addr().String()
}

// UntrustedAddr returns the paired loopback listener used by reserved
// untrusted sink hostnames.
func (f *WSFixture) UntrustedAddr() string {
	if f.untrustedListener == nil {
		return ""
	}
	return f.untrustedListener.Addr().String()
}

// WSURL returns the full WebSocket URL for connecting.
func (f *WSFixture) WSURL() string {
	return fmt.Sprintf("ws://%s/echo", f.listener.Addr().String())
}

// Messages returns the number of application messages that reached the fixture.
func (f *WSFixture) Messages() int64 { return f.messages.Load() }

// StartWS creates and starts a WebSocket echo server on a random port.
func StartWS() (*WSFixture, error) {
	ln, untrustedLn, err := listenLoopbackPair()
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := &WSFixture{
		listener:          ln,
		untrustedListener: untrustedLn,
	}
	mux := http.NewServeMux()
	mux.Handle("/echo", websocket.Handler(func(ws *websocket.Conn) {
		for {
			var msg wsFixtureMessage
			if err := wsFixtureCodec.Receive(ws, &msg); err != nil {
				return
			}
			f.messages.Add(1)
			if err := wsFixtureCodec.Send(ws, msg); err != nil {
				return
			}
		}
	}))
	// Health check for readiness.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	})

	// Separate *http.Server per listener keeps the trusted and untrusted sink
	// listeners fully isolated and unambiguously shut down.
	f.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	f.untrustedServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = f.server.Serve(ln) }()
	go func() { _ = f.untrustedServer.Serve(untrustedLn) }()
	return f, nil
}

// Close stops both WebSocket listeners.
func (f *WSFixture) Close() {
	_ = f.server.Close()
	_ = f.untrustedServer.Close()
}
