package fixture

import "fmt"

// Manager starts and manages all test fixtures for a gauntlet run.
// The adapter queries the manager for fixture addresses when routing cases.
type Manager struct {
	http *HTTPFixture
	tls  *TLSFixture
	ws   *WSFixture
	dns  *DNSFixture
}

// StartAll starts all fixtures. Call Close() when done.
func StartAll() (*Manager, error) {
	h, err := StartHTTP()
	if err != nil {
		return nil, fmt.Errorf("HTTP fixture: %w", err)
	}

	t, err := StartTLS()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("TLS fixture: %w", err)
	}

	w, err := StartWS()
	if err != nil {
		h.Close()
		t.Close()
		return nil, fmt.Errorf("WS fixture: %w", err)
	}

	d, err := StartDNS()
	if err != nil {
		h.Close()
		t.Close()
		w.Close()
		return nil, fmt.Errorf("DNS fixture: %w", err)
	}

	return &Manager{http: h, tls: t, ws: w, dns: d}, nil
}

// HTTP returns the HTTP response fixture.
func (m *Manager) HTTP() *HTTPFixture { return m.http }

// TLS returns the TLS fixture.
func (m *Manager) TLS() *TLSFixture { return m.tls }

// WS returns the WebSocket fixture.
func (m *Manager) WS() *WSFixture { return m.ws }

// DNS returns the DNS fixture.
func (m *Manager) DNS() *DNSFixture { return m.dns }

// Close stops all fixtures and cleans up temp files.
func (m *Manager) Close() {
	if m.http != nil {
		m.http.Close()
	}
	if m.tls != nil {
		m.tls.Close()
	}
	if m.ws != nil {
		m.ws.Close()
	}
	if m.dns != nil {
		m.dns.Close()
	}
}
