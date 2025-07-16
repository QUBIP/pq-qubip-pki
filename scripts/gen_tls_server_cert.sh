#!/bin/bash
# This script automates the creation of the QUBIP PKI

# script to generate a request token with a timestamp and hash of CSR
# echo `date -u +%Y%m%d%H%M` `sha256sum <r2.csr` \| sed "s/[ -]//g"
cd ..
CA="qubip-tls-ca"
ROOT_CA="qubip-root-ca"
WORKING_DIR=$(pwd)
CA_DIR="$WORKING_DIR/certs"
ROOT_CA_DIR="$CA_DIR/$ROOT_CA"
TLS_CA_DIR="$CA_DIR/$CA"
TLS_CA_CHAIN="$TLS_CA_DIR/$CA-chain.pem.der"
CONF_DIR="$WORKING_DIR/etc"
CERTS_DIR="$TLS_CA_DIR/newcerts"
CRT_FILE="$3"
CSR_FILE="$4"
KEY_FILE="$5"
CHAIN_FILE=$CRT_FILE-chain.pem.der
# PASS_FILE="$CA_PRIVATE_DIR/.tls_ca_passphrase.txt"
cd $WORKING_DIR

echo $1 $2 $3 $4 $5
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <CN> <subj> <cert_file> <csr_file> <key_file>, provided $# arguments"
    exit 1
fi

echo "Generating end entity key and CSR..."
openssl req -new \
    -keyout $KEY_FILE \
    -config $CONF_DIR/qubip-server.conf \
    -subj "$2" \
    -out $CSR_FILE

# Check if the CSR was created successfully
if [[ -f "$CSR_FILE" ]]; then
    echo "Successfully created end entity CSR: $CSR_FILE"
else
    echo "Failed to create end entity CSR!"
    exit 1
fi

# Generate certificate
echo -e "\nCreating end entity certificate issued by TLS CA..."

openssl ca  \
    -config etc/$CA.conf \
    -in $CSR_FILE \
    -out $CRT_FILE \
    -extensions server_ext \
    -days 7305

# Check if the certificate was created successfully
if [[ -f "$CRT_FILE" ]]; then
    echo "Successfully created end entity certificate: $CRT_FILE"
else
    echo "Failed to create end entity certificate!"
    exit 1
fi

echo "Converting certificate to DER format..."
openssl x509 \
    -in $CRT_FILE \
    -out ${CRT_FILE}.der \
    -outform der

if [[ $? -eq 0 ]]; then
    echo "Certificate successfully converted to DER format."
else
    echo "Error converting certificate to DER format."
fi

echo -e "\n\nGenerating certifiate chain file...\n"

cat ${CRT_FILE}.der $TLS_CA_CHAIN > \
    ${CHAIN_FILE}.der

exit 0
