package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// TLSStub stands in for a participant's ttyd: the portal builds the terminal
// iframe as https://<user>.<suffix> when the page loads (ADR-0031 D1 (b)), so
// every scenario needs something at that origin or the load becomes an
// external request. It serves one fixed page over TLS with a throw-away
// self-signed key; the browser is told to trust that key's SPKI only
// (--ignore-certificate-errors-spki-list), never to skip certificate checks in
// general.
type TLSStub struct {
	host string
	ln   net.Listener
	srv  *http.Server
	spki string

	mu   sync.Mutex
	hits []string
	once sync.Once
}

// NewTLSStub serves host (e.g. "user1.e2e.test") on a free loopback port.
func NewTLSStub(host string) (*TLSStub, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	t := &TLSStub{host: host, ln: ln, spki: base64.StdEncoding.EncodeToString(sum[:])}
	t.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.mu.Lock()
		t.hits = append(t.hits, r.Method+" "+r.Host+r.URL.Path)
		t.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><meta charset=utf-8><title>ttyd stub</title><p>ttyd stub</p>"))
	})}
	go func() { _ = t.srv.Serve(ln) }()
	return t, nil
}

// Host is the name the stub answers to.
func (t *TLSStub) Host() string { return t.host }

// Origin is the https origin the portal's iframe points at (default port).
func (t *TLSStub) Origin() string { return "https://" + t.host }

// Addr is the loopback host:port the name must be mapped to.
func (t *TLSStub) Addr() string { return t.ln.Addr().String() }

// SPKIHash is the base64 SHA-256 of the stub's public key, in the form
// --ignore-certificate-errors-spki-list takes.
func (t *TLSStub) SPKIHash() string { return t.spki }

// Hits returns "METHOD host/path" for every request the stub has served.
func (t *TLSStub) Hits() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.hits...)
}

// Close stops the stub.
func (t *TLSStub) Close() { t.once.Do(func() { _ = t.srv.Close() }) }
