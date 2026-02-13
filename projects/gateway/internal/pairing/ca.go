package pairing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	pairingCAKeyFileName  = "pairing_ca_key.pem"
	pairingCACertFileName = "pairing_ca_cert.pem"
	defaultCertTTL        = 365 * 24 * time.Hour
	defaultCATTL          = 10 * 365 * 24 * time.Hour
)

type IssuedCertificate struct {
	CertificatePEM      string
	CertificateChainPEM []string
	SerialNumber        string
	Fingerprint         string
	NotBefore           time.Time
	NotAfter            time.Time
}

type CertificateIssuer interface {
	IssueFromCSR(csrPEM string, componentID string) (IssuedCertificate, error)
}

type CertificateAuthority struct {
	cert    *x509.Certificate
	signer  crypto.Signer
	certPEM string
}

func LoadOrCreateCertificateAuthority(keyDir, gatewayID string) (*CertificateAuthority, error) {
	keyDir = strings.TrimSpace(keyDir)
	if keyDir == "" {
		return nil, fmt.Errorf("keyDir is required")
	}
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return nil, fmt.Errorf("gatewayID is required")
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	certPath := filepath.Join(keyDir, pairingCACertFileName)
	keyPath := filepath.Join(keyDir, pairingCAKeyFileName)

	certExists, err := fileExists(certPath)
	if err != nil {
		return nil, fmt.Errorf("stat ca cert: %w", err)
	}
	keyExists, err := fileExists(keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat ca key: %w", err)
	}
	if certExists && keyExists {
		return loadCertificateAuthority(certPath, keyPath)
	}
	if certExists != keyExists {
		return nil, fmt.Errorf("pairing ca cert/key files must both exist or both be absent")
	}

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate pairing ca key: %w", err)
	}
	now := time.Now().UTC()
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate ca serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pinchy-pairing-ca-" + gatewayID},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(defaultCATTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated ca certificate: %w", err)
	}
	certPEM, err := encodeCertificatePEM(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := encodeECPrivateKeyPEM(signer)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		return nil, fmt.Errorf("write ca cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write ca key file: %w", err)
	}

	return &CertificateAuthority{
		cert:    cert,
		signer:  signer,
		certPEM: certPEM,
	}, nil
}

func (c *CertificateAuthority) CAPEM() string {
	if c == nil {
		return ""
	}
	return c.certPEM
}

func (c *CertificateAuthority) IssueFromCSR(csrPEM string, componentID string) (IssuedCertificate, error) {
	if c == nil || c.cert == nil || c.signer == nil {
		return IssuedCertificate{}, fmt.Errorf("certificate authority not initialized")
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return IssuedCertificate{}, err
	}

	subject := csr.Subject
	if strings.TrimSpace(subject.CommonName) == "" {
		componentID = strings.TrimSpace(componentID)
		if componentID != "" {
			subject.CommonName = componentID
		} else {
			subject.CommonName = "pinchy-remote"
		}
	}

	now := time.Now().UTC()
	serial, err := randomSerial()
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("generate cert serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(defaultCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		DNSNames:       append([]string(nil), csr.DNSNames...),
		IPAddresses:    append([]net.IP(nil), csr.IPAddresses...),
		URIs:           append([]*url.URL(nil), csr.URIs...),
		EmailAddresses: append([]string(nil), csr.EmailAddresses...),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.signer)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("create signed certificate: %w", err)
	}
	issuedCert, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("parse issued certificate: %w", err)
	}
	issuedPEM, err := encodeCertificatePEM(der)
	if err != nil {
		return IssuedCertificate{}, err
	}

	return IssuedCertificate{
		CertificatePEM:      issuedPEM,
		CertificateChainPEM: []string{c.certPEM},
		SerialNumber:        issuedCert.SerialNumber.Text(16),
		Fingerprint:         sha256Fingerprint(issuedCert.Raw),
		NotBefore:           issuedCert.NotBefore.UTC(),
		NotAfter:            issuedCert.NotAfter.UTC(),
	}, nil
}

func loadCertificateAuthority(certPath, keyPath string) (*CertificateAuthority, error) {
	certPEMBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert file: %w", err)
	}
	keyPEMBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEMBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("parse ca cert pem: invalid certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	signer, err := parseSignerPEM(keyPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}

	return &CertificateAuthority{
		cert:    cert,
		signer:  signer,
		certPEM: string(certPEMBytes),
	}, nil
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: missing csr pem block", ErrProtocolViolation)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse csr: %v", ErrProtocolViolation, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: invalid csr signature: %v", ErrProtocolViolation, err)
	}
	return csr, nil
}

func parseSignerPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid key pem")
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer")
	}
	return signer, nil
}

func encodeCertificatePEM(der []byte) (string, error) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func encodeECPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal ca private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() <= 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func sha256Fingerprint(rawCert []byte) string {
	sum := sha256.Sum256(rawCert)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
