package fixture

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWSFixturePermissiveRSV1AcceptsFrame(t *testing.T) {
	f, err := StartWS()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	conn, err := net.DialTimeout("tcp", f.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn,
		"GET /permissive-rsv1 HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		f.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	_ = resp.Body.Close()

	payload := []byte("rsv1 fixture probe")
	mask := []byte{1, 2, 3, 4}
	frame := []byte{0xc1, 0x80 | byte(len(payload))}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%len(mask)])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatal(err)
	}
	if header[0] != 0x81 || int(header[1]) != len(payload) {
		t.Fatalf("echo header = %x, want ordinary text frame", header)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
	if got := f.Messages(); got != 1 {
		t.Fatalf("messages = %d, want 1", got)
	}
}

func TestWSFixturePermissiveRSV1RecordsEmptyClose(t *testing.T) {
	f, err := StartWS()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	conn, err := net.DialTimeout("tcp", f.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn,
		"GET /permissive-rsv1 HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		f.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_ = conn.Close()

	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for f.RSV1ClosedBeforeMessage() == 0 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("permissive fixture did not record terminal empty close")
		}
	}
}
