#!/bin/bash

# Thanks to https://dev.to/techschoolguru/how-to-create-sign-ssl-tls-certificates-2aai

#BACKUP_SRV_IP="192.168.10.20"
BACKUP_SRV_IP="127.0.0.1"
NAME="backup_srv"

# Generate CA's private key and self-signed certificate
gen_TLS_CA_cert() {
    openssl req -newkey rsa:4096 \
    -new \
    -x509 \
    -sha256 \
    -days 3650 \
    -nodes \
    -keyout rootCA-key.key \
    -out rootCA-cert.pem \
    -subj "/C=CH/ST=Zurich/L=Zurich/O=ASL/OU=ProjectHS2021-ROOTCA/CN=RootCA"
}

# Generate web server's private key and certificate signing request (CSR)
gen_TLS_CSR() {
    openssl req -newkey rsa:4096 \
    -new \
    -nodes \
    -out $1_TLS_CSR.pem \
    -keyout $1_TLS_CSR.key \
    -subj "/C=CH/ST=Zurich/L=Zurich/O=ASL/OU=ProjectHS2021/CN=$NAME"
}

# Use CA's private key to sign web server's CSR and get back the signed certificate
sign_TLS_CSR() {
    openssl x509 -req \
    -in $1_TLS_CSR.pem \
    -days 3650 \
    -CA rootCA-cert.pem \
    -CAkey rootCA-key.key \
    -CAcreateserial \
    -out $1_TLS_CSR_signed.pem \
    -extfile $2
}

# Generate ROOT CA
gen_TLS_CA_cert

# Generate backup server TLS certificate and key and sign it with root CA
gen_TLS_CSR $NAME
echo "subjectAltName=IP:$BACKUP_SRV_IP" > backup-ext.cnf
sign_TLS_CSR $NAME backup-ext.cnf

# Add lines below to generate similar certificates
