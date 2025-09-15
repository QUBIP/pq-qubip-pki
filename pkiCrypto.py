
import sys
import logging
import os
import subprocess
import json, re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pprint
import shlex

classical_algorithms = ['rsa2048', 'rsa4096', 'ed25519']

pq_algorithms = ['mldsa44', 'mldsa65', 'mldsa87', 'mldsa44_ed25519', 'mldsa65_ed25519']
cas = ['qubip-root-ca', 'qubip-mcu-ca', 'qubip-mpu-ca']
chains = ['certs', 'pki-65', 'pki-44']
OPENSSL_MODULES = "/home/torseec/quantumsafe/build/lib/ossl-modules"
OQS_CONF = "/opt/pki-file/oqs.cnf"

def generate_private_key(openssl, pki, key_file, algorithm):
    if pki == 'pki-44':
# add BOTH env vars inline
        openssl_cmd = f'OPENSSL_CONF={shlex.quote(OQS_CONF)} OPENSSL_MODULES={shlex.quote(OPENSSL_MODULES)} {openssl}'
        # include provider flags so we don’t depend on oqs.cnf content
        provider_flags = f'-provider oqsprovider -provider default -provider-path {shlex.quote(OPENSSL_MODULES)} -propquery provider=oqsprovider'
    else:
        if algorithm == 'mldsa44_ed25519':
            openssl_cmd = f'OPENSSL_CONF={shlex.quote(OQS_CONF)} OPENSSL_MODULES={shlex.quote(OPENSSL_MODULES)} {openssl}'
        else:
            openssl_cmd = openssl
    if algorithm in classical_algorithms:
        if algorithm == 'rsa2048':
            cmd = f"{openssl_cmd} genpkey -algorithm RSA -out {key_file} -pkeyopt rsa_keygen_bits:2048"
        elif algorithm == 'rsa4096':
            cmd = f"{openssl_cmd} genpkey -algorithm RSA -out {key_file} -pkeyopt rsa_keygen_bits:4096"

        elif algorithm == 'ed25519':
            cmd = f"{openssl_cmd} genpkey -algorithm ed25519 -out {key_file}"
    elif algorithm in pq_algorithms:
        cmd = f"{openssl_cmd} genpkey -algorithm {algorithm} -out {key_file}"
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    try:
        subprocess.check_output(cmd, shell=True, text=True).strip()
        if not os.path.isfile(key_file):
            raise FileNotFoundError(f"Failed to create private key: {key_file}")
    except subprocess.CalledProcessError as e:
        sys.exit(1)

def generate_csr(openssl, pki, private_key, csr_filename, subject, conf, commonName, subjectAltName, cn_type):
    env = os.environ
    if pki == 'pki-44':
        openssl_cmd = f'OPENSSL_CONF={shlex.quote(OQS_CONF)} OPENSSL_MODULES={shlex.quote(OPENSSL_MODULES)} {openssl}'
    else:
        openssl_cmd = openssl
    if subjectAltName != "":  
        # server or client
        logging.info(f"SAN = {subjectAltName}")
        env["SAN"] = subjectAltName
        logging.info(env["SAN"])
        if cn_type == "fqdn":
            reqexts = "fqdn_ext"
        elif cn_type == "ip":
            reqexts = "ip_ext"
    logging.info(reqexts)
    try:
        cmd = f"{openssl_cmd} req -new -key {private_key} -out {csr_filename} -subj {subject} -config {conf} -reqexts {reqexts}"
        subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        logging.info(f"Error generating CSR: {e}")
        sys.exit(1)

def sign_certificate(openssl, pki, csr_file, crt_file, purpose, ca_key, ca_passfile, ca_cert, ca_conf):
    if purpose == 'server':
        ext = 'server_ext'
    elif purpose == 'client':
        ext = 'client_ext'
    if pki == 'pki-44':
        openssl_cmd = f'OPENSSL_CONF={shlex.quote(OQS_CONF)} OPENSSL_MODULES={shlex.quote(OPENSSL_MODULES)} {openssl}'
        
    else:
        openssl_cmd = openssl
    try:
        cmd = f"{openssl_cmd} ca -config {ca_conf} -keyfile {ca_key} -passin file:{ca_passfile} -cert {ca_cert} -in {csr_file} -out {crt_file} -extensions {ext} -days 365 -batch"
        subprocess.check_output(cmd, shell=True, text=True).strip()
        if os.path.isfile(crt_file):
            logging.info(f"Successfully created end entity certificate: {crt_file}")
            return
        else:
            raise FileNotFoundError(f"Failed to create certificate: {crt_file}")
    except subprocess.CalledProcessError as e:
        logging.info(f"Error generating certificate: {e}")
        sys.exit(1)

def convert_certificate_to_der(openssl, pki, crt_file):
    if pki == 'pki-44':
        openssl_cmd = f'OPENSSL_CONF={shlex.quote(OQS_CONF)} OPENSSL_MODULES={shlex.quote(OPENSSL_MODULES)} {openssl}'
        
    else:
        openssl_cmd = openssl
    try:
        der_file = f"{crt_file}.der"
        cmd = f"{openssl_cmd} x509 -in {crt_file} -out {der_file} -outform DER"
        subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error converting certificate to DER format: {e}")

def create_certificate_chain(cert_file, ca_chain, chain_file):
    try:
        with open(chain_file, "wb") as chain:
            print(chain_file)
            with open(cert_file, "rb") as cert:
                chain.write(cert.read())
                cert.close()
            with open(ca_chain, "rb") as ca:
                print(ca_chain)
                chain.write(ca.read())
                ca.close()
        logging.info(f"Certificate chain successfully created: {chain_file}")
        chain.close()
    except Exception as e:
        logging.info(f"Error creating certificate chain: {e}")

# functions called by viewing ca certs/crl APIs

def get_ca_certificate_details(openssl, ca_cert_path):
    cert_command = f"{openssl} x509 -in {ca_cert_path} -noout -text -certopt no_sigdump"    
    ca_cert_data = ""
    ca_cert_data = subprocess.check_output(cert_command, shell=True, text=True).strip()
    return ca_cert_data

def get_crl_details(openssl, crl_path):
    crl_command = f"{openssl} crl -in {crl_path} -noout -text | sed '/Signature Value/,/^$/d'"
    crl_data = ""
    crl_data = subprocess.check_output(crl_command, shell=True, text=True).strip()
    return crl_data
