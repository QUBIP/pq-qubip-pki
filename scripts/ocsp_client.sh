#!/bin/bash

# This script automates the creation of the QUBIP PKI

#WORKING_DIR="/home/lab7nuc/quantumsafe/QUBIP/WP1/PKI/post-quantum-pki/pq_composite_v1"
WORKING_DIR=$(pwd)
CA_DIR="certs"

ROOT_CA_DIR="$CA_DIR/qubip-root-ca"
ROOT_CA_CERT="$ROOT_CA_DIR/qubip-root-ca-cert.pem"
TLS_CA_DIR="$CA_DIR/tls-ca"
TLS_CA_CERT="$TLS_CA_DIR/tls-ca-cert.pem"
DB_DIR="$TLS_CA_DIR/db"
CERTS_DIR="$TLS_CA_DIR/certs"
CRT_FILE="$CERTS_DIR/tls-ca-ocsp.pem"
KEY_FILE="$CERTS_DIR/tls-ca-ocsp.key"
echo -e "Query OCSP Responder"
cd $WORKING_DIR
cd ..

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <CN>"
    exit 1
fi

openssl ocsp \
    -url http://localhost:8081 \
    -CAfile $ROOT_CA_CERT \
    -issuer $TLS_CA_CERT \
    -cert $CERTS_DIR/${1}.pem \
    -respout ocsp_response.der
    
