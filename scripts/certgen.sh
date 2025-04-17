#!/bin/bash

mkdir -p ../certs

openssl ecparam -genkey -name prime256v1 -noout -out ../certs/server.key
openssl req -new -x509 -key ../certs/server.key -out ../certs/server.crt -days 365 \
    -subj "/C=BR/ST=SP/L=City/O=MyOrg/CN=localhost"
