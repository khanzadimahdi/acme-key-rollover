package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	jose "github.com/go-jose/go-jose/v4"
)

type Payload struct {
	Account string          `json:"account"`
	OldKey  jose.JSONWebKey `json:"oldKey"`
}

// encodeBase64URL encodes the payload to base64 URL encoding.
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// JsonMarshal encodes the payload to json
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

// Sign the payload with the old account key using RSA.
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

func loadKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("No valid PEM data found")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

var (
	accountID = 1905259936

	directoryURL = "https://acme-v02.api.letsencrypt.org/acme/new-nonce"

	// ACME KeyChange URL for Let's Encrypt (Production URL)
	acmeKeyChangeURL = "https://acme-v02.api.letsencrypt.org/acme/key-change"

	// Account ID (Kid) - This would be obtained from your account metadata in a real-world scenario.
	kid = fmt.Sprintf("https://acme-v02.api.letsencrypt.org/acme/acct/%d", accountID)
)

func main() {
	oldKeyData, err := os.ReadFile("old-private-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	oldKey, _ := loadKey(oldKeyData)

	newKeyData, err := os.ReadFile("new-private-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	newKey, _ := loadKey(newKeyData)

	payload := Payload{
		Account: kid,
		OldKey:  toJwk(oldKey),
	}
	innerPayload := signPayload(acmeKeyChangeURL, newKey, newKey, "", []byte(JsonMarshal(payload)))
	requestPayload := signPayload(acmeKeyChangeURL, oldKey, nil, kid, []byte(innerPayload))

	//	os.WriteFile("request.json", []byte(requestPayload), os.ModeAppend)

	fmt.Println(requestPayload)

	// Make the POST request
	resp, err := http.Post(acmeKeyChangeURL, "application/jose+json", bytes.NewBuffer([]byte((requestPayload))))
	if err != nil {
		fmt.Printf("Error sending POST request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to rollover key, status: %s\n", resp.Status)

		b, _ := io.ReadAll(resp.Body)
		fmt.Println(string(b))

		return
	}

	fmt.Println("Key rollover successful!")
}
