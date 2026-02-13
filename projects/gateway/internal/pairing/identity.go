package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const identityFileName = "gateway_identity.json"

type GatewayIdentity struct {
	GatewayID  string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func (g *GatewayIdentity) PublicKeyBase64() string {
	if g == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(g.PublicKey)
}

func LoadOrCreateIdentity(keyDir, gatewayID string) (*GatewayIdentity, error) {
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

	path := filepath.Join(keyDir, identityFileName)
	if _, err := os.Stat(path); err == nil {
		return loadIdentity(path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat identity file: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	record := identityFileRecord{
		GatewayID:         gatewayID,
		PrivateKeyEd25519: base64.StdEncoding.EncodeToString(priv),
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal identity file: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write identity file: %w", err)
	}

	return &GatewayIdentity{
		GatewayID:  gatewayID,
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

func loadIdentity(path string) (*GatewayIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	var record identityFileRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	if strings.TrimSpace(record.GatewayID) == "" {
		return nil, fmt.Errorf("identity file missing gateway_id")
	}

	privateBytes, err := base64.StdEncoding.DecodeString(record.PrivateKeyEd25519)
	if err != nil {
		return nil, fmt.Errorf("decode private_key_ed25519: %w", err)
	}
	if len(privateBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private_key_ed25519 size")
	}

	priv := ed25519.PrivateKey(privateBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return &GatewayIdentity{
		GatewayID:  record.GatewayID,
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

type identityFileRecord struct {
	GatewayID         string `json:"gateway_id"`
	PrivateKeyEd25519 string `json:"private_key_ed25519"`
}
