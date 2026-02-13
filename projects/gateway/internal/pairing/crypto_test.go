package pairing

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptChallenge(t *testing.T) {
	curve := ecdh.X25519()
	remotePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote x25519 private key: %v", err)
	}
	remotePubB64 := base64.StdEncoding.EncodeToString(remotePriv.PublicKey().Bytes())

	ciphertext, aad, err := encryptChallenge(remotePubB64, "pair_1", "challenge_1", "hello")
	if err != nil {
		t.Fatalf("encrypt challenge: %v", err)
	}
	plaintext, err := decryptChallenge(remotePriv, ciphertext, aad)
	if err != nil {
		t.Fatalf("decrypt challenge: %v", err)
	}
	if plaintext != "hello" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
}
