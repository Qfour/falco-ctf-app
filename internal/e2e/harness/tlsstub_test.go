package harness

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
	// Wait returns at once on a hit already seen (E4 waits on this, not on a clock)...
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := stub.Wait(ctx, "the request above", func(h []string) bool { return len(h) == 1 }); err != nil {
		t.Errorf("Wait on a hit already seen: %v", err)
	}
	// ...a Wait that is never satisfied ends with the deadline and says what the stub saw...
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	err = stub.Wait(short, "a second request", func(h []string) bool { return len(h) == 2 })
	if err == nil || !strings.Contains(err.Error(), "deadline") || !strings.Contains(err.Error(), "GET ") {
		t.Errorf("an unsatisfied Wait returned %v, want the deadline and the hits seen", err)
	}
	// ...and Close releases one.
	done := make(chan error, 1)
	go func() { done <- stub.Wait(context.Background(), "nothing", func([]string) bool { return false }) }()
	stub.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("Wait after Close returned %v, want closed", err)
	}
}
