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
		"GET /permissive-rsv1/accept HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
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
	markedFrames, terminalClose := f.RSV1Outcome("accept")
	if markedFrames != 1 || terminalClose {
		t.Fatalf("outcome = marked:%d terminal:%v, want one marked frame only", markedFrames, terminalClose)
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
		"GET /permissive-rsv1/close HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
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
	for {
		markedFrames, terminalClose := f.RSV1Outcome("close")
		if terminalClose {
			if markedFrames != 0 {
				t.Fatal("empty-close outcome also reported a marked frame")
			}
			otherMarked, otherTerminal := f.RSV1Outcome("other")
			if otherMarked != 0 || otherTerminal {
				t.Fatalf("other marker inherited outcome = marked:%d terminal:%v", otherMarked, otherTerminal)
			}
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("permissive fixture did not record terminal empty close")
		}
	}
}

func TestWSFixturePermissiveRSV1CountsOnlyCompleteFragmentedMessage(t *testing.T) {
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
		"GET /permissive-rsv1/fragment HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		f.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if err := writeMaskedFixtureTestFrame(conn, 0x41, []byte("hello ")); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		markedFrames, _ := f.RSV1Outcome("fragment")
		if markedFrames == 1 {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("fixture did not record the initial fragment")
		}
	}
	if got := f.Messages(); got != 0 {
		t.Fatalf("messages after initial fragment = %d, want 0", got)
	}

	if err := writeMaskedFixtureTestFrame(conn, 0x80, []byte("world")); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatal(err)
	}
	if header[0] != 0x81 || header[1] != byte(len("hello world")) {
		t.Fatalf("echo header = %x, want completed text frame", header)
	}
	echo := make([]byte, len("hello world"))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "hello world" {
		t.Fatalf("echo = %q, want complete fragmented payload", echo)
	}
	if got := f.Messages(); got != 1 {
		t.Fatalf("messages after final continuation = %d, want 1", got)
	}
}

func TestWSFixturePermissiveRSV1TracksMarkedFrameNotGenericData(t *testing.T) {
	f, err := StartWS()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	t.Run("ordinary frame before close is not marked delivery", func(t *testing.T) {
		conn, reader := openPermissiveFixture(t, f, "ordinary-first")
		if err := writeMaskedFixtureTestFrame(conn, 0x81, []byte("ordinary")); err != nil {
			t.Fatal(err)
		}
		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			t.Fatal(err)
		}
		echo := make([]byte, int(header[1]))
		if _, err := io.ReadFull(reader, echo); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		waitForRSV1Outcome(t, f, "ordinary-first", 0, true)
	})

	t.Run("marked control frame is recorded", func(t *testing.T) {
		conn, _ := openPermissiveFixture(t, f, "control")
		if err := writeMaskedFixtureTestFrame(conn, 0xc9, []byte("probe")); err != nil {
			t.Fatal(err)
		}
		waitForRSV1Outcome(t, f, "control", 1, false)
		_ = conn.Close()
	})
}

func openPermissiveFixture(t *testing.T, f *WSFixture, marker string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", f.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn,
		"GET /permissive-rsv1/%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		marker, f.Addr()); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return conn, reader
}

func waitForRSV1Outcome(t *testing.T, f *WSFixture, marker string, wantMarked int, wantTerminal bool) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		marked, terminal := f.RSV1Outcome(marker)
		if marked == wantMarked && terminal == wantTerminal {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("outcome = marked:%d terminal:%v, want marked:%d terminal:%v", marked, terminal, wantMarked, wantTerminal)
		}
	}
}

func writeMaskedFixtureTestFrame(w io.Writer, firstByte byte, payload []byte) error {
	mask := []byte{1, 2, 3, 4}
	frame := []byte{firstByte, 0x80 | byte(len(payload))}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%len(mask)])
	}
	_, err := w.Write(frame)
	return err
}
