package pairing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type challengeAAD struct {
	PairingID                string `json:"pairing_id"`
	ChallengeID              string `json:"challenge_id"`
	EphemeralPublicKeyX25519 string `json:"ephemeral_public_key_x25519"`
}

func randomBase64(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func encryptChallenge(remotePublicX25519Base64, pairingID, challengeID, plaintext string) (string, string, error) {
	remotePubRaw, err := base64.StdEncoding.DecodeString(remotePublicX25519Base64)
	if err != nil {
		return "", "", fmt.Errorf("decode remote public x25519: %w", err)
	}
	curve := ecdh.X25519()
	remotePub, err := curve.NewPublicKey(remotePubRaw)
	if err != nil {
		return "", "", fmt.Errorf("parse remote public x25519: %w", err)
	}

	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ephemeral x25519 key: %w", err)
	}
	shared, err := ephPriv.ECDH(remotePub)
	if err != nil {
		return "", "", fmt.Errorf("derive shared secret: %w", err)
	}

	aad := challengeAAD{
		PairingID:                pairingID,
		ChallengeID:              challengeID,
		EphemeralPublicKeyX25519: base64.StdEncoding.EncodeToString(ephPriv.PublicKey().Bytes()),
	}
	aadBytes, err := json.Marshal(aad)
	if err != nil {
		return "", "", fmt.Errorf("marshal aad: %w", err)
	}

	key := deriveSymmetricKey(shared, aadBytes)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), aadBytes)
	payload := append(nonce, sealed...)

	return base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(aadBytes), nil
}

func decryptChallenge(privateKey *ecdh.PrivateKey, ciphertextBase64, aadBase64 string) (string, error) {
	aadBytes, err := base64.StdEncoding.DecodeString(aadBase64)
	if err != nil {
		return "", fmt.Errorf("decode aad: %w", err)
	}
	var aad challengeAAD
	if err := json.Unmarshal(aadBytes, &aad); err != nil {
		return "", fmt.Errorf("parse aad: %w", err)
	}

	ephPubRaw, err := base64.StdEncoding.DecodeString(aad.EphemeralPublicKeyX25519)
	if err != nil {
		return "", fmt.Errorf("decode ephemeral public key: %w", err)
	}
	curve := ecdh.X25519()
	ephPub, err := curve.NewPublicKey(ephPubRaw)
	if err != nil {
		return "", fmt.Errorf("parse ephemeral public key: %w", err)
	}

	shared, err := privateKey.ECDH(ephPub)
	if err != nil {
		return "", fmt.Errorf("derive shared secret: %w", err)
	}
	key := deriveSymmetricKey(shared, aadBytes)

	payload, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	if len(payload) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := payload[:gcm.NonceSize()]
	ciphertext := payload[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aadBytes)
	if err != nil {
		return "", fmt.Errorf("decrypt challenge: %w", err)
	}
	return string(plaintext), nil
}

func deriveSymmetricKey(sharedSecret, aad []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(aad)
	sum := h.Sum(nil)
	key := make([]byte, 32)
	copy(key, sum)
	return key
}
