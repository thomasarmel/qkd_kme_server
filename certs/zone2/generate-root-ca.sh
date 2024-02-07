#!/usr/bin/env bash

openssl genrsa -out "CA-zone2.key" 4096
openssl req -new -key "CA-zone2.key" -out "CA-zone2.csr" -sha256 -subj '/CN=Root CA for KME in zone2'
openssl x509 -req -days 3650 -in "CA-zone2.csr" -signkey "CA-zone2.key" -sha256 -out "CA-zone2.crt" -extfile "root-ca.cnf" -extensions root_ca
sudo cp CA-zone2.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
