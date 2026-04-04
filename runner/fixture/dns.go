package fixture

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// DNSFixture runs a lightweight DNS server for testing DNS rebinding detection.
// It returns different IPs on successive queries for the same hostname,
// simulating the rebinding attack pattern where an attacker-controlled domain
// resolves to a public IP first, then to a private/internal IP.
type DNSFixture struct {
	server  *dns.Server
	addr    string
	mu      sync.Mutex
	records map[string]*rebindRecord
}

// rebindRecord tracks a sequence of IPs to return for a hostname.
type rebindRecord struct {
	ips   []string // sequence of IPs to return
	index atomic.Int64
}

// Addr returns the DNS server address (host:port).
func (f *DNSFixture) Addr() string { return f.addr }

// SetRebind configures a hostname to return different IPs on successive lookups.
// First query returns ips[0], second returns ips[1], etc. Wraps around.
func (f *DNSFixture) SetRebind(hostname string, ips []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Ensure hostname ends with a dot (DNS FQDN format).
	if hostname[len(hostname)-1] != '.' {
		hostname += "."
	}
	f.records[hostname] = &rebindRecord{ips: ips}
}

// StartDNS creates and starts a DNS server on a random UDP port.
func StartDNS() (*DNSFixture, error) {
	// Find a free UDP port.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()

	f := &DNSFixture{
		addr:    addr,
		records: make(map[string]*rebindRecord),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		for _, q := range r.Question {
			if q.Qtype != dns.TypeA {
				continue
			}

			f.mu.Lock()
			rec, ok := f.records[q.Name]
			f.mu.Unlock()

			if !ok {
				// Unknown hostname — return NXDOMAIN.
				msg.Rcode = dns.RcodeNameError
				break
			}

			// Rotate through the IP sequence.
			idx := rec.index.Add(1) - 1
			ip := rec.ips[idx%int64(len(rec.ips))]

			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0, // no caching
				},
				A: net.ParseIP(ip),
			})
		}

		_ = w.WriteMsg(msg)
	})

	server := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	f.server = server

	started := make(chan struct{})
	go func() {
		server.NotifyStartedFunc = func() { close(started) }
		_ = server.ListenAndServe()
	}()
	<-started

	return f, nil
}

// Close stops the DNS server.
func (f *DNSFixture) Close() {
	_ = f.server.Shutdown()
}
