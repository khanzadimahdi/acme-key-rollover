package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v4"
)

func readFile(name string) []byte {
	data, err := os.ReadFile(name)
	if err != nil {
		log.Fatalf("error on reading %s: %s", name, err)
	}

	return data
}

func parseKey(privateKey []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(privateKey)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatalf("No valid PEM data found")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Can't parse private key: %s", err)
	}

	return key
}

func JsonMarshal(v any) []byte {
	j, err := json.Marshal(v)
	if err != nil {
		log.Fatal(err)
	}

	return j
}

func toJwk(key crypto.PrivateKey) jose.JSONWebKey {
	jwk := jose.JSONWebKey{Key: key, KeyID: kid}

	return jwk.Public()
}

func signPayload(url string, oldKey *rsa.PrivateKey, newKey *rsa.PrivateKey, kid string, payload []byte) string {
	signKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: oldKey, KeyID: kid},
	}

	options := jose.SignerOptions{
		NonceSource: NoneSourceFunc(getNonce),
		EmbedJWK:    len(kid) == 0,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if newKey != nil {
		options.ExtraHeaders["jwk"] = toJwk(newKey)
	}

	signer, err := jose.NewSigner(signKey, &options)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to create jose signer: %w", err))
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to sign content: %w", err))
	}

	return signed.FullSerialize()
}

type NoneSourceFunc func() (string, error)

func (n NoneSourceFunc) Nonce() (string, error) {
	return n()
}

// getNonce retrieves a fresh nonce from the ACME server.
func getNonce() (string, error) {
	resp, err := http.Head(directoryURL)
	if err != nil {
		return "", fmt.Errorf("error getting nonce: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get nonce, status code: %d", resp.StatusCode)
	}

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("nonce not found in response header")
	}

	return nonce, nil
}
