package pairing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCertificateAuthority_PersistsAcrossLoads(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	first, err := LoadOrCreateCertificateAuthority(keyDir, "gw_test")
	if err != nil {
		t.Fatalf("create certificate authority: %v", err)
	}
	second, err := LoadOrCreateCertificateAuthority(keyDir, "gw_test")
	if err != nil {
		t.Fatalf("load certificate authority: %v", err)
	}
	if first.CAPEM() != second.CAPEM() {
		t.Fatalf("expected same CA cert across loads")
	}
}

func TestCertificateAuthority_IssueFromCSR(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	ca, err := LoadOrCreateCertificateAuthority(keyDir, "gw_test")
	if err != nil {
		t.Fatalf("create certificate authority: %v", err)
	}

	csrPEM, err := generateCSRPEM("tool-1")
	if err != nil {
		t.Fatalf("generate csr: %v", err)
	}
	issued, err := ca.IssueFromCSR(csrPEM, "tool-1")
	if err != nil {
		t.Fatalf("issue from csr: %v", err)
	}
	if issued.CertificatePEM == "" {
		t.Fatalf("expected certificate pem")
	}
	if issued.Fingerprint == "" {
		t.Fatalf("expected certificate fingerprint")
	}
	if len(issued.CertificateChainPEM) == 0 {
		t.Fatalf("expected certificate chain")
	}

	issuedCert, err := parseCertPEM(issued.CertificatePEM)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	caCert, err := parseCertPEM(ca.CAPEM())
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	if issuedCert.Issuer.String() != caCert.Subject.String() {
		t.Fatalf("expected issued cert to be signed by CA")
	}
}

func TestCertificateAuthority_IssueFromCSRRejectsInvalidCSR(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	ca, err := LoadOrCreateCertificateAuthority(keyDir, "gw_test")
	if err != nil {
		t.Fatalf("create certificate authority: %v", err)
	}

	_, err = ca.IssueFromCSR("not-a-csr", "tool-1")
	if err == nil {
		t.Fatalf("expected invalid csr to fail")
	}
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("expected protocol violation, got %v", err)
	}
}

func generateCSRPEM(commonName string) (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{"tool.local"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("missing certificate pem block")
	}
	return x509.ParseCertificate(block.Bytes)
}
