
newkey:
	openssl genrsa -traditional -out new-private-key.pem 2048

run:
	go run .
