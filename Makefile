generate-newkey:
	openssl genrsa -traditional -out new-private-key.pem 2048

run:
	go run . \
	-account-id 12345 \
	-old-key-path "./old-private-key.pem" \
	-new-key-path "./new-private-key.pem"

.PHONY: run generate-newkey
