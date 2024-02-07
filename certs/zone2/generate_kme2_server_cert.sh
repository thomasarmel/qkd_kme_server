#!/usr/bin/env bash

openssl req -new -nodes -out kme2.csr -newkey rsa:4096 -keyout kme2.key -subj '/CN=localhost/C=FR/ST=Biot/L=Biot/O=Unice'
openssl x509 -req -in kme2.csr -CA CA-zone2.crt -CAkey CA-zone2.key -CAcreateserial -out kme2.crt -days 3650 -sha256 -extfile kme2.v3.ext
