#!/usr/bin/env bash

ARGC=$#

if [ $ARGC -ne 1 ]
then
  echo "Invalid number of arguments"
  exit
fi

openssl genrsa -out "root-ca-$1.key" 4096
openssl req -new -key "root-ca-$1.key" -out "root-ca-$1.csr" -sha256 -subj "/CN=Inter-KME $1 Root CA"
openssl x509 -req -days 3650 -in "root-ca-$1.csr" -signkey "root-ca-$1.key" -sha256 -out "root-ca-$1.crt" -extfile "root-ca.cnf" -extensions root_ca
