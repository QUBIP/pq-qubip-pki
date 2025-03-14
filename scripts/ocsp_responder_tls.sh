#!/bin/bash

# This script automates the creation of the QUBIP PKI

#WORKING_DIR="/home/lab7nuc/quantumsafe/QUBIP/WP1/PKI/post-quantum-pki/pq_composite_v1"
WORKING_DIR=$(pwd)
CA_DIR="certs"
ROOT_CA_DIR="$CA_DIR/qubip-root-ca"
TLS_CA_DIR="$CA_DIR/tls-ca"
TLS_CA_CERT="$TLS_CA_DIR/tls-ca-cert.pem"
DB_DIR="$TLS_CA_DIR/db"
CERTS_DIR="$TLS_CA_DIR/certs"
CRT_FILE="$CERTS_DIR/tls-ca-ocsp.pem"
KEY_FILE="$CERTS_DIR/tls-ca-ocsp.key"
# Generate private key and CSR
cd $WORKING_DIR
cd ..
echo -e "Start OCSP responder (TLS CA)"
openssl ocsp \
    -url http://localhost:8081 \
    -index $DB_DIR/tls-ca.db \
    -CA $TLS_CA_CERT \
    -rsigner $CRT_FILE \
    -rkey $KEY_FILE \
    -text \
    -out responder_log.txt \
    -ndays 1