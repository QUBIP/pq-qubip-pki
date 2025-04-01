
import sys
import logging
import os
import subprocess
import json, re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pprint

classical_algorithms = ['rsa2048', 'rsa4096', 'ed25519']

pq_algorithms = ['mldsa44', 'mldsa65', 'mldsa87', 'mldsa44_ed25519', 'mldsa65_ed25519']
cas = ['qubip-root-ca', 'qubip-software-ca', 'qubip-tls-ca']
env = os.environ.copy()
logging.basicConfig(level=logging.INFO)

# functions called by /generate_certificate API

def retrieve_ca_info(config, ca, cert_id):
    if ca == 'qubip-tls-ca':
        ca_dir = config['TLS_CA_DIR']
        certs_dir = config['TLS_CERTS_DIR']
        key_file = config['TLS_CA_KEY']
        ca_passfile = config['TLS_CA_PASSWORD']
        ca_cert = config['TLS_CA_CERT']
        ca_conf = config['TLS_CA_CONF']
        ca_chain = config['TLS_CA_CHAIN']
    elif ca == 'qubip-software-ca':
        ca_dir = config['SOFTWARE_CA_DIR']
        certs_dir = config['SOFTWARE_CERTS_DIR']
        key_file = config['SOFTWARE_CA_KEY']
        ca_passfile = config['SOFTWARE_CA_PASSWORD']
        ca_cert = config['SOFTWARE_CA_CERT']
        ca_conf = config['SOFTWARE_CA_CONF']
        ca_chain = config['SOFTWARE_CA_CHAIN']
    key_file = os.path.join(certs_dir, f'{cert_id}.key')
    csr_file = os.path.join(certs_dir, f'{cert_id}.csr')
    cert_file = os.path.join(certs_dir, f'{cert_id}-cert.pem')
    ca_key = os.path.join(ca_dir, 'private',f'{ca}.key')

    # logging.info(f"CA directory: {ca_dir}")
    # logging.info(f"Certificates directory: {certs_dir}")
    # logging.info(f"key: {key_file}")
    # logging.info(f"CA password file: {ca_passfile}")
    # logging.info(f"CA certificate: {ca_cert}")
    # logging.info(f"CA configuration: {ca_conf}")
    # logging.info(f"CA chain: {ca_chain}")
    # logging.info(f"CSR file: {csr_file}")
    # logging.info(f"Certificate file: {cert_file}")

    return key_file, csr_file, cert_file, ca_key, ca_passfile, ca_cert, ca_conf, ca_chain

def generate_private_key(key_file, algorithm):
    if algorithm in classical_algorithms:
        if algorithm == 'rsa2048':
            subprocess.run([
                "openssl", "genpkey", "-algorithm"              , "RSA", "-out", key_file, "-pkeyopt", f"rsa_keygen_bits:2048"
            ], check=True)
        elif algorithm == 'rsa4096':
            subprocess.run([
                "openssl", "genpkey", "-algorithm", "RSA", "-out", key_file, "-pkeyopt", f"rsa_keygen_bits:4096"
            ], check=True)
        elif algorithm == 'ed25519':
            subprocess.run([
                "openssl", "genpkey", "-algorithm", "ed25519", "-out", key_file
            ], check=True)
    elif algorithm in pq_algorithms:
        logging.debug(f"Generating {algorithm} private key.")
        subprocess.run([
                "openssl", "genpkey", "-algorithm", algorithm, "-out", key_file
            ], check=True)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    try:
        
        if not os.path.isfile(key_file):
            raise FileNotFoundError(f"Failed to create private key: {key_file}")
    except subprocess.CalledProcessError as e:
        sys.exit(1)

def generate_csr(private_key, csr_filename, subject, conf, commonName, subjectAltName, cn_type):
    if subjectAltName != "":  
        # tls-server or tls-client
        logging.info("SAN ENVIRONMENT VARIABLE")
        env["SAN"] = subjectAltName
        logging.info(env["SAN"])
        if cn_type == "fqdn":
            reqexts = "fqdn_ext"
        elif cn_type == "ip":
            reqexts = "ip_ext"
    else:
        # codesign
        reqexts = "codesign_reqext"
    logging.info(reqexts)
    try:
        subprocess.run([
            "openssl", "req", "-new", 
            "-key", private_key, 
            "-out", csr_filename, 
            "-subj", subject,
            "-config", conf,
            "-reqexts", reqexts
            ], env=env, check=True)
    except subprocess.CalledProcessError as e:
        logging.info(f"Error generating CSR: {e}")
        sys.exit(1)

def sign_certificate(csr_file, crt_file, purpose, ca_key, ca_passfile, ca_cert, ca_conf):
    if purpose == 'tls-server':
        ext = 'server_ext'
    elif purpose == 'tls-client':
        ext = 'client_ext'
    elif purpose == 'code-signing':
        ext = 'codesign_ext'
    try:
        subprocess.run([
            "openssl", "ca",
            "-config", ca_conf,
            "-keyfile", ca_key,
            "-passin", f"file:{ca_passfile}", # automate password input
            "-cert", ca_cert,
            "-in", csr_file,
            "-out", crt_file,
            "-extensions", ext,
            "-days", "365",
            "-batch" # automatically approve signing
        ], check=True)
        if os.path.isfile(crt_file):
            logging.info(f"Successfully created end entity certificate: {crt_file}")
            return crt_file
        else:
            raise FileNotFoundError(f"Failed to create certificate: {crt_file}")
    except subprocess.CalledProcessError as e:
        logging.info(f"Error generating certificate: {e}")
        sys.exit(1)

def convert_certificate_to_der(crt_file):
    try:
        der_file = f"{crt_file}.der"
        subprocess.run([
            "openssl", "x509",
            "-in", crt_file,
            "-out", der_file,
            "-outform", "der"
        ], check=True)
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

def get_ca_certificate_details(ca_cert_path):
    cert_command = f"openssl x509 -in {ca_cert_path} -noout -text"
    ca_cert_data = ""
    ca_cert_data = subprocess.check_output(cert_command, shell=True, text=True).strip()
    return ca_cert_data

def get_crl_details(crl_path):
    crl_command = f"openssl crl -in {crl_path} -noout -text"
    crl_data = ""
    crl_data = subprocess.check_output(crl_command, shell=True, text=True).strip()
    return crl_data
