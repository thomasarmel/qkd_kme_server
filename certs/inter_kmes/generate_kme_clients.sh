#!/usr/bin/env bash

ARGC=$#

if [ $ARGC -ne 2 ]
then
  echo "Invalid number of arguments"
  echo "Usage: $0 kmeclient kmeserver"
  exit
fi

openssl genrsa -out "client-$1-to-$2.key" 4096
openssl req -new -key "client-$1-to-$2.key" -out "client-$1-to-$2.csr" -sha256 -subj '/CN=KME network Client $1 to $2'
openssl x509 -req -days 750 -in "client-$1-to-$2.csr" -sha256 -CA "root-ca-$2.crt" -CAkey "root-ca-$2.key" -CAcreateserial -out "client-$1-to-$2.crt" -extfile "inter-kme-client.cnf" -extensions client
cat "client-$1-to-$2.key" "client-$1-to-$2.crt" "root-ca-$2.crt" > "client-$1-to-$2.pem"
openssl pkcs12 -export -out "client-$1-to-$2.pfx" -inkey "client-$1-to-$2.key" -in "client-$1-to-$2.pem" -certfile "root-ca-$2.crt"
