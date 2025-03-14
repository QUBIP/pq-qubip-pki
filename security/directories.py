
import os
CERTS_DIR = './certs/'
ROOT_CA = 'qubip-root-ca'
TLS_CA = 'qubip-tls-ca'
SOFTWARE_CA = 'qubip-software-ca'
ROOT_CA_DIR = "./certs/qubip-root-ca"
TLS_CA_DIR = "./certs/qubip-tls-ca"
SOFTWARE_CA_DIR = "./certs/qubip-software-ca"
TLS_CERTS_DIR = "./certs/qubip-tls-ca/newcerts"
SOFTWARE_CERTS_DIR = "./certs/qubip-software-ca/newcerts"
CONF_DIR = './etc'
TLS_CA_CONF = "./etc/qubip-tls-ca.conf"
SOFTWARE_CA_CONF = "./etc/qubip-software-ca.conf"
OPENSSL_CONF_FILE = "./etc/qubip-openssl.conf"
TLS_SERVER_CONF = "./etc/qubip-server.conf"
TLS_CLIENT_CONF = "./etc/qubip-client.conf"
CODESIGN_CONF = "./etc/qubip-codesign.conf"
IDENTITY_CONF = "./etc/qubip-identity.conf" # not created yet
TLS_CA_KEY = "./certs/qubip-tls-ca/private/qubip-tls-ca.key"
TLS_CA_CERT = "./certs/qubip-tls-ca/qubip-tls-ca-cert.pem"
SOFTWARE_CA_KEY = "./certs/qubip-software-ca/private/qubip-software-ca.key"
SOFTWARE_CA_CERT = "./certs/qubip-software-ca/qubip-software-ca-cert.pem"
TLS_PASSWORD=os.path.join(TLS_CERTS_DIR, '/private/.qubip-tls-ca-passphrase.txt')
SOFTWARE_CA_PASSWORD=os.path.join(SOFTWARE_CERTS_DIR, '/private/.qubip-software-ca-passphrase.txt')
TLS_CA_CHAIN="./certs/qubip-tls-ca/qubip-tls-ca-chain.pem.der"
SOFTWARE_CA_CHAIN="./certs/qubip-software-ca/qubip-software-ca-chain.pem.der"