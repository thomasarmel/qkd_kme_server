#!/usr/bin/env bash

SAE="sae3"

openssl genrsa -out "$SAE.key" 4096
openssl req -new -key "$SAE.key" -out "$SAE.csr" -sha256 -subj "/CN=$SAE Client certificate"
openssl x509 -req -days 3650 -in "$SAE.csr" -sha256 -CA "CA-zone2.crt" -CAkey "CA-zone2.key" -CAcreateserial -out "$SAE.crt" -extfile "client.cnf" -extensions client
cat "$SAE.key" "$SAE.crt" "CA-zone2.crt" > "$SAE.pem"
openssl pkcs12 -export -out "$SAE.pfx" -inkey "$SAE.key" -in "$SAE.pem" -certfile "CA-zone2.crt"
