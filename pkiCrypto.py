
import sys
import logging
import os
import subprocess
import json, re
from security import directories
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pprint

classical_algorithms = ['rsa2048', 'rsa4096', 'ed25519']

pq_algorithms = ['mldsa44', 'mldsa65', 'mldsa87']
cas = ['qubip-root-ca', 'qubip-software-ca', 'qubip-tls-ca']
env = os.environ.copy()

def retrieve_ca_info(ca, cert_id):
    logging.debug(f"pkiCrypto.py - Retrieving CA information for {ca}")
    if ca == 'qubip-tls-ca':
        ca_dir = directories.TLS_CA_DIR
    elif ca == 'qubip-software-ca':
        ca_dir = directories.SOFTWARE_CA_DIR
    certs_dir = os.path.join(ca_dir, 'newcerts')
    key_file = os.path.join(certs_dir, f'{cert_id}.key')
    csr_file = os.path.join(certs_dir, f'{cert_id}.csr')
    cert_file = os.path.join(certs_dir, f'{cert_id}-cert.pem')
    ca_key = os.path.join(ca_dir, 'private',f'{ca}.key')
    ca_passfile = os.path.join(ca_dir, 'private', f'.{ca}-passphrase.txt')
    ca_cert = os.path.join(ca_dir, f'{ca}-cert.pem')
    ca_conf = os.path.join(directories.CONF_DIR, f'{ca}.conf')
    ca_chain = os.path.join(ca_dir, f'{ca}-chain.pem')

    return key_file, csr_file, cert_file, ca_key, ca_passfile, ca_cert, ca_conf, ca_chain

def generate_private_key(key_file, algorithm):
    """Generate a private key using the specified algorithm."""
    # Determine the OpenSSL command based on the chosen algorithm
    if algorithm in classical_algorithms:
        logging.debug("pkiCrypto.py - Generating {algorithm} private key.")
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
        
        if os.path.isfile(key_file):
            logging.info(f"Successfully created private key using {algorithm}: {key_file}")
        else:
            raise FileNotFoundError(f"Failed to create private key: {key_file}")
    except subprocess.CalledProcessError as e:
        logging.info(f"Error generating private key: {e}")
        sys.exit(1)

def generate_csr(private_key, csr_filename, subject, conf, commonName, subjectAltName, cn_type):
    if subjectAltName != "":  
        # print("SAN NOT EMPTY")          
        env["SAN"] = subjectAltName
        # print(env["SAN"])
        if cn_type == "fqdn":
            reqexts = "fqdn_ext"
        elif cn_type == "ip":
            reqexts = "ip_ext"
    else:
        # codesign
        reqexts = "codesign_reqext"
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
            "-days", "7305",
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

    """Convert the certificate to DER format."""
    print("Converting certificate to DER format...")
    try:
        der_file = f"{crt_file}.der"
        subprocess.run([
            "openssl", "x509",
            "-in", crt_file,
            "-out", der_file,
            "-outform", "der"
        ], check=True)
        logging.info(f"Certificate successfully converted to DER format: {der_file}")
    except subprocess.CalledProcessError as e:
        logging.info(f"Error converting certificate to DER format: {e}")

def create_certificate_chain(cert_file, ca_chain, chain_file):
    """Create a certificate chain file."""
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

def load_certificate(cert_path):
    """Loads and parses the X.509 certificate."""
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

def get_certificate_details(cert_id, cert_path, chain_path):
    """ Extracts relevant certificate details for display. """
    cert = load_certificate(cert_path)
    print(cert_path)
    subj_key_algorithm_command = f"openssl x509 -in {cert_path} -noout -text | grep -i 'Public Key Algorithm' | head -n 1 | awk '{{print $4}}'"
    print(subj_key_algorithm_command)
    subj_key_algorithm = ""
    subj_key_algorithm = subprocess.check_output(subj_key_algorithm_command, shell=True, text=True).strip()
    issuer_key_algorithm_command = f"openssl x509 -in {cert_path} -noout -text | grep -i 'Signature Algorithm' | head -n 1 | awk '{{print $3}}'"
    issuer_key_algorithm = ""
    issuer_key_algorithm = subprocess.check_output(issuer_key_algorithm_command, shell=True, text=True).strip()
    public_key = extract_pq_key_material(cert)
    ip_address_command = f"openssl x509 -in {cert_path} -noout -text | grep -i 'IP Address'"
    ip_address = ""
    if cert_id in cas:
        ip_address = ""
    else:
        ip_address = subprocess.check_output(ip_address_command, shell=True, text=True).strip()
        
    logging.debug("pkiCrypto.py - IP ADDRESS")
    logging.debug(ip_address)
    print("ISSUER KEY ALGORITHM = ", issuer_key_algorithm)
    print("SUBJECT KEY ALGORITHM = ", subj_key_algorithm)
    key_usage = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
    key_usage_flags = {
    "Digital Signature": key_usage.digital_signature,
    "Key Encipherment": key_usage.key_encipherment,
    "Content Commitment": key_usage.content_commitment,
    "Data Encipherment": key_usage.data_encipherment,
    "Key Agreement": key_usage.key_agreement,
    "Key Cert Sign": key_usage.key_cert_sign,
    "CRL Sign": key_usage.crl_sign
    }
    enabled_flags = [flag for flag, enabled in key_usage_flags.items() if enabled]
    certificate_policies = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CERTIFICATE_POLICIES).value
    policy_oids = [str(policy.policy_identifier) for policy in certificate_policies]
    # Get details
    cert_info = {
        "cert_id": cert_id,
        "subject_common_name": cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        "issuer_country": cert.issuer.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value,
        "issuer_common_name": cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        "not_before": cert.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "not_after": cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "san": ip_address,
        "subject_algorithm": subj_key_algorithm, # TODO public key
        "serial_number": format(cert.serial_number, "x"),
        "signature_algorithm": issuer_key_algorithm,  
        "version": cert.version.name,
        "download": [cert_path, chain_path],
        "basic_constraints": "N/A",
        "key_usage": enabled_flags,
        "extended_key_usage": "N/A",
        "Issuer": cert.issuer.rfc4514_string(),
        "subject_key_id": cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex(),
        "authority_key_id": cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier.hex(),
        "aia": cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value[0].access_location.value,
        "certificate_policies": policy_oids,
        "crl_distribution_points": cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS).value[0].full_name[0].value
    }

    return cert_info

def extract_pq_key_material(cert):
    text = str(cert)
    print(text)
    match = re.search(r'PQ key material:\s*((?:\s*[0-9a-f]{2}(:[0-9a-f]{2})*:?[\s]*)+)', text, re.IGNORECASE)

    if match:
        hex_bytes = match.group(1)
        # Cleaning up whitespace and colons
        hex_bytes = hex_bytes.replace(" ", "").replace(":\n", "").replace("\n", "").replace(":", " ")
        print("Extracted PQ Key Material:")
        print(hex_bytes)
        return hex_bytes
    else:
        print("PQ key material not found.")
        return "N/A"
