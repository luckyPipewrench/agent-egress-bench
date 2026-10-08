package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// TestSVGPairTransparentDelivery exercises the committed pair over CONNECT and
// TLS. Both responses pass unchanged through the proxy; this checks delivery.
func TestSVGPairTransparentDelivery(t *testing.T) {
	fm, err := fixture.StartAll()
	if err != nil {
		t.Fatal(err)
	}
	defer fm.Close()
	ca, err := tls.LoadX509KeyPair(fm.TLS().CAFile(), fm.TLS().KeyFile())
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"aeb-fixture.test", "api.vendor.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	rawCA, err := os.ReadFile(fm.TLS().CAFile())
	if err != nil {
		t.Fatal(err)
	}
	roots.AppendCertsFromPEM(rawCA)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "aeb-fixture.test", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	var seen atomic.Int64
	delivered := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		defer secured.Close()
		req, err := http.ReadRequest(bufio.NewReader(secured))
		if err != nil {
			t.Error(err)
			return
		}
		defer req.Body.Close()
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://"+fm.TLS().Addr()+req.URL.RequestURI(), nil)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := client.Do(upReq)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if resp.Header.Get("Content-Type") != "image/svg+xml" {
			t.Errorf("wire content type: %s", resp.Header.Get("Content-Type"))
		}
		seen.Add(1)
		delivered <- string(body)
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
		resp.Close = true
		_ = resp.Write(secured)
	}))
	defer proxy.Close()
	pa, err := adapter.NewProxyAdapter(proxy.Listener.Addr().String(), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	pa.SetTLSFixtureWithContentType(fm.TLS().Addr(), fm.TLS().CAFile(), fm.TLS().SetRouteWithContentType, fm.TLS().SetRouteForHostWithContentType)
	pa.SetTLSRequestCounter(fm.TLS().Requests)
	for _, tc := range []struct {
		id        string
		wantScore string
	}{
		{"response-mitm-svg-script-009", "fail"},
		{"response-mitm-svg-benign-010", "pass"},
	} {
		id := tc.id
		t.Run(id, func(t *testing.T) {
			raw, err := os.ReadFile("../cases/response-mitm/" + id + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var source Case
			if err = json.Unmarshal(raw, &source); err != nil {
				t.Fatal(err)
			}
			c := adapter.Case{ID: source.ID, InputType: source.InputType, Transport: source.Transport, Requires: source.Requires, Payload: source.Payload}
			before := fm.TLS().Requests()
			result := pa.Run(c, 3*time.Second)
			if result.Err != nil || result.Verdict != "allow" || !result.VerdictObserved || !result.DeliveryProven {
				t.Fatalf("%s: %+v", id, result)
			}
			// A transparent target misses the attack. Preserve the corpus's
			// expected verdict and score that miss, rather than inventing a block.
			if score := scoreCaseWithEvidence(source, result.Verdict, result.Evidence); score != tc.wantScore {
				t.Fatalf("transparent response scored %q, want %q", score, tc.wantScore)
			}
			if fm.TLS().Requests() != before+1 {
				t.Fatalf("%s never delivered its response", id)
			}
			select {
			case body := <-delivered:
				if body != source.Payload["response_body"] {
					t.Fatalf("response body changed: %q", body)
				}
			default:
				t.Fatal("proxy did not observe the response body")
			}
		})
	}
	if seen.Load() != 2 {
		t.Fatalf("measured %d responses, want 2", seen.Load())
	}
}
