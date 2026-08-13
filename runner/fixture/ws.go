package fixture

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // WebSocket RFC 6455 mandates SHA-1 for the upgrade accept value.
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
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
	rsv1Mu            sync.RWMutex
	rsv1Outcomes      map[string]rsv1Outcome
}

type rsv1Outcome struct {
	markedRSV1Frames int
	terminalClose    bool
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

// RSV1Outcome returns how many marked RSV1 frames reached one permissive
// connection and whether that upgraded connection reached a terminal close.
func (f *WSFixture) RSV1Outcome(marker string) (markedRSV1Frames int, terminalClose bool) {
	f.rsv1Mu.RLock()
	defer f.rsv1Mu.RUnlock()
	outcome := f.rsv1Outcomes[marker]
	return outcome.markedRSV1Frames, outcome.terminalClose
}

// StartWS creates and starts a WebSocket echo server on a random port.
func StartWS() (*WSFixture, error) {
	ln, untrustedLn, err := listenLoopbackPair()
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := &WSFixture{
		listener:          ln,
		untrustedListener: untrustedLn,
		rsv1Outcomes:      make(map[string]rsv1Outcome),
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
	// The ordinary WebSocket library correctly rejects RSV1 when compression
	// was not negotiated. That makes it unsuitable as an attribution fixture:
	// close 1002 could then come from either the proxy or the destination. This
	// deliberately permissive endpoint accepts the raw frame instead and records
	// whether the marked RSV1 frame reached its exact connection.
	mux.HandleFunc("/permissive-rsv1/", f.servePermissiveRSV1)
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

const webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func (f *WSFixture) servePermissiveRSV1(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	marker := strings.TrimPrefix(r.URL.Path, "/permissive-rsv1/")
	hijacker, ok := w.(http.Hijacker)
	if key == "" || marker == "" || strings.Contains(marker, "/") || !ok {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck // fixture connection cleanup
	handshakeComplete := false
	defer func() {
		if handshakeComplete {
			f.recordRSV1TerminalClose(marker)
		}
	}()
	acceptInput := []byte(key + webSocketGUID)
	acceptSum := sha1.Sum(acceptInput) //nolint:gosec // Required by RFC 6455, not used for security.
	if _, err := fmt.Fprintf(conn,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(acceptSum[:])); err != nil {
		return
	}
	handshakeComplete = true
	var fragmentedOpcode byte
	var fragmentedPayload []byte
	for {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		opcode, fin, rsv1, payload, err := readPermissiveClientFrame(rw.Reader)
		if err != nil {
			return
		}
		if rsv1 {
			f.recordMarkedRSV1(marker)
		}
		if opcode == 8 {
			return
		}
		switch opcode {
		case 1, 2:
			if fragmentedOpcode != 0 {
				return
			}
			if !fin {
				fragmentedOpcode = opcode
				fragmentedPayload = append(fragmentedPayload[:0], payload...)
				continue
			}
		case 0:
			if fragmentedOpcode == 0 {
				return
			}
			if len(fragmentedPayload)+len(payload) > 1<<20 {
				return
			}
			fragmentedPayload = append(fragmentedPayload, payload...)
			if !fin {
				continue
			}
			opcode = fragmentedOpcode
			payload = fragmentedPayload
			fragmentedOpcode = 0
			fragmentedPayload = nil
		default:
			continue
		}
		f.messages.Add(1)
		if err := writePermissiveServerFrame(conn, opcode, payload); err != nil {
			return
		}
	}
}

func (f *WSFixture) recordMarkedRSV1(marker string) {
	f.rsv1Mu.Lock()
	outcome := f.rsv1Outcomes[marker]
	outcome.markedRSV1Frames++
	f.rsv1Outcomes[marker] = outcome
	f.rsv1Mu.Unlock()
}

func (f *WSFixture) recordRSV1TerminalClose(marker string) {
	f.rsv1Mu.Lock()
	outcome := f.rsv1Outcomes[marker]
	outcome.terminalClose = true
	f.rsv1Outcomes[marker] = outcome
	f.rsv1Mu.Unlock()
}

func readPermissiveClientFrame(r *bufio.Reader) (byte, bool, bool, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, false, false, nil, err
	}
	opcode := header[0] & 0x0f
	fin := header[0]&0x80 != 0
	rsv1 := header[0]&0x40 != 0
	masked := header[1]&0x80 != 0
	payloadLen := uint64(header[1] & 0x7f)
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, false, false, nil, err
		}
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, false, false, nil, err
		}
		payloadLen = 0
		for _, b := range ext {
			payloadLen = payloadLen<<8 | uint64(b)
		}
	}
	if !masked || payloadLen > 1<<20 {
		return 0, false, false, nil, fmt.Errorf("invalid fixture frame")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(r, mask); err != nil {
		return 0, false, false, nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, false, false, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	return opcode, fin, rsv1, payload, nil
}

func writePermissiveServerFrame(w io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		return fmt.Errorf("fixture payload too large")
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// Close stops both WebSocket listeners.
func (f *WSFixture) Close() {
	_ = f.server.Close()
	_ = f.untrustedServer.Close()
}
