#!/bin/bash

cd ..
WORKING_DIR=$(pwd)

CA_DIR="$WORKING_DIR/certs"
ROOT_CA_DIR="$CA_DIR/qubip-root-ca"
TLS_CA_DIR="$CA_DIR/tls-ca"
CERTS_DIR="$TLS_CA_DIR/certs"
CA_PRIVATE_DIR="$TLS_CA_DIR/private"
CONF_DIR="$WORKING_DIR/etc"
TLS_CONF_FILE="$CONF_DIR/tls-ca.conf"
OCSP_CONF_FILE="$CONF_DIR/ocsp.conf"
ROOT_CONF_FILE="$CONF_DIR/qubip-root-ca.conf"
CSR_FILE="$CERTS_DIR/tls-ca-ocsp.csr"
KEY_FILE="$CERTS_DIR/tls-ca-ocsp.key"
ROOT_CRT_FILE="$ROOT_CA_DIR/qubip-root-ca-cert.pem"
CRT_FILE="$CERTS_DIR/tls-ca-ocsp.pem"
EXTENSIONS="ocspsign_ext"
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <algorithm>"
    exit 1
fi

echo -e "OCSP SETUP (TLS CA)"
cd $WORKING_DIR
echo -e "------------------------------------------------------"
echo -e "Create OCSP signing request for OCSP responder"
openssl req -new \
    -keyout certs/tls-ca/certs/tls-ca-ocsp.key \
    -config etc/ocsp.conf \
    -out certs/tls-ca/certs/tls-ca-ocsp.csr \
    -newkey $1



if [[ -f "certs/tls-ca/certs/tls-ca-ocsp.csr" ]]; then
    echo "Successfully created OCSP CSR: certs/tls-ca-ocsp.csr"
else
    echo "Failed to create OCSP CSR!"
    exit 1
fi

echo -e "------------------------------------------------------"
echo -e "Generate OCSP signing certificate"
# openssl ca \
#     -config "$TLS_CA_CONF" \
#     -in "$CSR_FILE" \
#     -out "$CRT_FILE" \
#     -extensions "$EXTENSIONS" \
#     -days 14

openssl ca -config etc/tls-ca.conf -in certs/tls-ca/certs/tls-ca-ocsp.csr -out certs/tls-ca/certs/tls-ca-ocsp.pem -extensions ocspsign_ext -days 14

if [[ -f "certs/tls-ca/certs/tls-ca-ocsp.pem" ]]; then
    echo "Successfully created OCSP certificate: certs/tls-ca-ocsp.pem"
else
    echo "Failed to create OCSP certificate!"
    exit 1
fi

echo "Converting certificate to DER format..."
openssl x509 \
    -in "$CRT_FILE" \
    -out "${CRT_FILE}.der" \
    -outform der

if [[ $? -eq 0 ]]; then
    echo "Certificate successfully converted to DER format."
else
    echo "Error converting certificate to DER format."
fi

exit 0
