#!/bin/sh

openssl genrsa -out "bad_root-ca.key" 4096
openssl req -new -key "bad_root-ca.key" -out "bad_root-ca.csr" -sha256 -subj '/CN=Local Test Root CA'
openssl x509 -req -days 3650 -in "bad_root-ca.csr" -signkey "bad_root-ca.key" -sha256 -out "bad_root-ca.crt" -extfile "bad_root-ca.cnf" -extensions root_ca

openssl genrsa -out "bad_client.key" 2048
openssl req -new -key "bad_client.key" -out "bad_client.csr" -sha256 -subj '/CN=Local Test Client'
openssl x509 -req -days 750 -in "bad_client.csr" -sha256 -CA "bad_root-ca.crt" -CAkey "bad_root-ca.key" -CAcreateserial -out "bad_client.crt" -extfile "bad_client.cnf" -extensions client
cat bad_client.key bad_client.crt bad_root-ca.crt > bad_client.pem
openssl pkcs12 -export -out bad_client.pfx -inkey bad_client.key -in bad_client.pem -certfile bad_root-ca.crt