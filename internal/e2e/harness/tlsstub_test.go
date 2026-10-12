package harness

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
)

func TestTLSStub_ServesItsNameAndPublishesTheKeyHash(t *testing.T) {
	stub, err := NewTLSStub("user1.e2e.test")
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	if stub.Origin() != "https://user1.e2e.test" {
		t.Errorf("Origin = %q", stub.Origin())
	}
	var presented *x509.Certificate
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		ServerName:         "user1.e2e.test",
		InsecureSkipVerify: true, // the test checks the key hash itself, below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			presented, err = x509.ParseCertificate(raw[0])
			return err
		},
	}}}
	resp, err := client.Get("https://" + stub.Addr() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Errorf("stub answered %d with %q", resp.StatusCode, body)
	}
	sum := sha256.Sum256(presented.RawSubjectPublicKeyInfo)
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != stub.SPKIHash() {
		t.Errorf("SPKIHash %q is not the hash of the key the stub presents (%q)", stub.SPKIHash(), got)
	}
	if hits := stub.Hits(); len(hits) != 1 {
		t.Errorf("Hits = %v, want one", hits)
	}
}
