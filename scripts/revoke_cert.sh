#!/bin/bash

cd ..
WORKING_DIR=$(pwd)
CA_DIR="$WORKING_DIR/certs"
ROOT_CA_DIR="$CA_DIR/qubip-root-ca"
TLS_CA_DIR="$CA_DIR/tls-ca"
CA_DB="$TLS_CA_DIR/db/tls-ca.db"
CONF_DIR="$WORKING_DIR/etc"
TLS_CONF="/home/grace/demo_qubip/pki/pq_composite_v1/etc/tls-ca.conf "
CRL_DIR="$TLS_CA_DIR/crl"
CRL="$CRL_DIR/tls-ca.crl"

cd $WORKING_DIR
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <CN> <reason>"
    exit 1
fi
COMMON_NAME=$1
CERT_CODE="$(grep $COMMON_NAME $CA_DB | cut -f4)"
echo -e "Revoke certificate $COMMON_NAME.pem"

CERT_CODE=$(grep $1 $CA_DB | cut -f4)
CERT_NAME="$CERT_CODE.pem"
echo $CERT_NAME
openssl ca \
    -config $TLS_CONF \
    -revoke $TLS_CA_DIR/$CERT_NAME \
    -crl_reason $2

echo "Revoked"
echo "Update CRL"
openssl ca -gencrl \
    -config $TLS_CONF \
    -out $CRL

echo "CRL UPDATED"