package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
)

// This code implements only ACME key rollover
// RFC: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5

var (
	// ACME NewNonce URL for Let's Encrypt (Production URL)
	directoryURL = "https://acme-v02.api.letsencrypt.org/acme/new-nonce"

	// ACME KeyChange URL for Let's Encrypt (Production URL)
	acmeKeyChangeURL = "https://acme-v02.api.letsencrypt.org/acme/key-change"

	// Account ID (Kid) - This would be obtained from your account metadata in a real-world scenario.
	kid = "https://acme-v02.api.letsencrypt.org/acme/acct/%d"
)

type Payload struct {
	Account string          `json:"account"`
	OldKey  jose.JSONWebKey `json:"oldKey"`
}

var (
	oldKeyPath string
	newKeyPath string
	accountID  int64
)

func main() {
	flag.StringVar(&oldKeyPath, "old-key-path", "", "specifies the old private key absolute path")
	flag.StringVar(&newKeyPath, "new-key-path", "", "specifies the new private key absolute path")
	flag.Int64Var(&accountID, "account-id", 0, "specifies account ID")
	flag.Parse()

	// Validate
	if len(oldKeyPath) == 0 || len(newKeyPath) == 0 || accountID == 0 {
		fmt.Println("invalid data:\n  old-key-path, new-key-path and account-id are required")
		flag.Usage()
		return
	}

	kid = fmt.Sprintf(kid, accountID)

	// Reading keys
	oldKeyData := readFile(oldKeyPath)
	newKeyData := readFile(newKeyPath)

	// Parse keys
	oldKey := parseKey(oldKeyData)
	newKey := parseKey(newKeyData)

	// Preparing request payload
	payload := Payload{
		Account: kid,
		OldKey:  toJwk(oldKey),
	}
	innerPayload := signPayload(acmeKeyChangeURL, newKey, newKey, "", []byte(JsonMarshal(payload)))
	requestPayload := signPayload(acmeKeyChangeURL, oldKey, nil, kid, []byte(innerPayload))

	// Call ACME API
	resp, err := http.Post(acmeKeyChangeURL, "application/jose+json", bytes.NewBuffer([]byte((requestPayload))))
	if err != nil {
		fmt.Printf("Error sending POST request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Verify the results
	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Failed to rollover key, status: %s\n %s\n", resp.Status, string(b))

		return
	}

	fmt.Println("Key rollover successful!")
}
