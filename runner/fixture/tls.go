// Package fixture provides test infrastructure servers for the gauntlet runner.
// These fixtures enable testing of capabilities that require real backends:
// TLS interception (response-mitm cases), WebSocket relay (ws-dlp cases),
// and DNS rebinding (ssrf-bypass cases).
package fixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// TLSFixture runs a mock HTTPS server that returns configurable responses.
// Used with pipelock's TLS interception to test response-mitm cases.
// The fixture generates a self-signed CA and server cert on startup.
type TLSFixture struct {
	listener net.Listener
	server   *http.Server
	caFile   string // path to CA cert PEM (for pipelock config)
	keyFile  string // path to CA key PEM (for pipelock config)
	mu       sync.Mutex
	routes   map[string]string // path → response body
}

// TLSFixtureAddr returns the listener address (host:port).
func (f *TLSFixture) Addr() string {
	return f.listener.Addr().String()
}

// CAFile returns the path to the generated CA certificate PEM.
func (f *TLSFixture) CAFile() string { return f.caFile }

// KeyFile returns the path to the generated CA key PEM.
func (f *TLSFixture) KeyFile() string { return f.keyFile }

// SetRoute configures a response body for a given URL path.
func (f *TLSFixture) SetRoute(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = body
}

// StartTLS creates a TLS fixture with a self-signed CA and starts serving.
func StartTLS() (*TLSFixture, error) {
	// Generate CA key pair.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AEB Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// Write CA cert and key to temp files for pipelock config.
	caFile, err := os.CreateTemp("", "aeb-ca-cert-*.pem")
	if err != nil {
		return nil, fmt.Errorf("create CA cert file: %w", err)
	}
	_ = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	_ = caFile.Close()

	keyFile, err := os.CreateTemp("", "aeb-ca-key-*.pem")
	if err != nil {
		return nil, fmt.Errorf("create CA key file: %w", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	_ = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = keyFile.Close()

	// Generate server cert signed by CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "*.example.com", "*.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create server cert: %w", err)
	}

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}

	f := &TLSFixture{
		caFile: caFile.Name(),
		keyFile: keyFile.Name(),
		routes: make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		body, ok := f.routes[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		MinVersion:   tls.VersionTLS12,
	})

	f.listener = tlsLn
	f.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = f.server.Serve(tlsLn) }()
	return f, nil
}

// Close stops the TLS server and removes temp cert files.
func (f *TLSFixture) Close() {
	_ = f.server.Close()
	_ = os.Remove(f.caFile)
	_ = os.Remove(f.keyFile)
}
