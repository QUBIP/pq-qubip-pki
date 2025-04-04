from flask import Flask, request, render_template, jsonify, send_from_directory, url_for, send_file
import subprocess
import os
import uuid
import logging
import tempfile
from pkiCrypto import generate_private_key, generate_csr, sign_certificate, create_certificate_chain, get_ca_certificate_details, get_crl_details
from io import BytesIO # allows to create files without saving them on disk (useful for private key)
from zipfile import ZipFile 
from cryptography import x509
import base64
from cryptography.hazmat.backends import default_backend
from config import Config
import ssl
import getpass

# Setup logging
logging.basicConfig(level=logging.INFO)

# Initialize flask app
app = Flask(__name__, static_url_path='/static')

# Load configurations
app.config.from_object(Config)

# Validate configurations
Config.validate()
private_keys = {}  # Store private keys in memory
openssl = app.config['OPENSSL']

@app.route('/generate_certificate/<purpose>', methods=['GET','POST'])
def generate_certificate(purpose):
    if request.method == 'GET':
        return render_template('gen-cert.html', purpose=purpose)
    if request.method == 'POST':
        try:
            data = request.json or request.form
            if purpose == 'tls-server' or purpose == 'tls-client':
                ca = app.config['TLS_CA']
                ca_certs_dir = app.config['TLS_CERTS_DIR']
                ca_conf = app.config['TLS_CA_CONF']
                ca_key_file = app.config['TLS_CA_KEY']
                ca_passfile = app.config['TLS_CA_PASSWORD']
                ca_cert = app.config['TLS_CA_CERT']
                ca_chain = app.config['TLS_CA_CHAIN']
                if purpose == 'tls-server':
                    conf_file = app.config['TLS_SERVER_CONF']
                else:
                    conf_file = app.config['TLS_CLIENT_CONF']
            elif purpose == 'code-signing':
                ca = app.config['SOFTWARE_CA']
                ca_certs_dir = app.config['SOFTWARE_CERTS_DIR']
                ca_conf = app.config['SOFTWARE_CA_CONF']
                ca_key_file = app.config['SOFTWARE_CA_KEY']
                ca_passfile = app.config['SOFTWARE_CA_PASSWORD']
                ca_cert = app.config['SOFTWARE_CA_CERT']
                conf_file = app.config['CODESIGN_CONF']
                ca_chain = app.config['SOFTWARE_CA_CHAIN']
            logging.info(data)
            algorithm = data.get('algorithm') 
            logging.debug(f"Using algorithm: {algorithm}")

            commonName = data.get('common_name')
            cn_type = data.get('cn_type') # IP/DNS/Email
            cert_id = f'{str(uuid.uuid4().hex[:10 ])}-{purpose}' 
            key_file = os.path.join(ca_certs_dir, f'{cert_id}.key')

            logging.debug(f"Generating certificate for {purpose} with commonName: {commonName}, algorithm: {algorithm}, cert_id: {cert_id}")
            generate_private_key(openssl, key_file, algorithm)
            if not key_file:
                return {"error": "Failed to generate private key"}, 500
            else:
                logging.info("PRIVATE KEY GENERATED")
                logging.info(f"Key file: {key_file}")
                with open(key_file, 'r') as key_fp:
                    private_keys[cert_id] = key_fp.read()
                key_fp.close()

                subjectAltName = ""
                if purpose != "code-signing":
                    subjectAltName = commonName
                    logging.info(f"SAN = {subjectAltName}")
                    subj = f"/C=EU/O=QUBIP/CN={commonName}"
                else:
                    subj = f"/C=EU/O=QUBIP/CN={commonName}/userId={cert_id}"
                csr_file = os.path.join(ca_certs_dir, f'{cert_id}.csr')
                generate_csr(openssl, key_file,csr_file, subj, conf_file, commonName, subjectAltName, cn_type)
                if not csr_file:
                    return jsonify({"error": "Failed to generate CSR"}), 500
                logging.info("CSR GENERATED")
                cert_file = os.path.join(ca_certs_dir, f'{cert_id}-cert.pem')
                sign_certificate(openssl, csr_file, cert_file, purpose, ca_key_file, ca_passfile, ca_cert, ca_conf)

                with open(cert_file, 'r') as cert_fp:
                    certificate = cert_fp.read()
                if not cert_file:
                    return jsonify({"error": "Failed to generate certificate"}), 500
                else:
                    chain_file = f'{cert_id}-chain.pem'
                    chain_path = os.path.join(ca_certs_dir, chain_file)
                    create_certificate_chain(cert_file, ca_chain, chain_path)
                    return jsonify({
                        'ca': ca,
                        'certificate_id': cert_id,
                        'certificate': certificate,
                        'filename': f'{cert_id}.pem'
                        }), 200
        except Exception as e:
            logging.error(f"Error generating certificate: {e}")
            return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 400

@app.route('/download_certificate/<ca>/<cert_id>', methods=['GET'])
def download_certificate(ca, cert_id):
    filename = f'{cert_id}-cert.pem'
    csr_file = f'{cert_id}.csr'
    chain_filename = f'{cert_id}-chain.pem'
    if ca == 'qubip-tls-ca':
        certs_path = app.config['TLS_CERTS_DIR']
    elif ca == 'qubip-software-ca':
        certs_path = app.config['SOFTWARE_CERTS_DIR']
    else:
        return jsonify({'error': 'CA not found'}), 404

    full_path = os.path.join(certs_path, filename) 
    full_chain_path = os.path.join(certs_path, chain_filename) 
    if not os.path.exists(full_path):
        return jsonify({'error': 'Certificate not found'}), 404
    key_filename = f'{cert_id}.key'
    key_content = private_keys.pop(cert_id, None)  # Retrieve and remove the private key from memory
    if  not key_content:
        return jsonify({'error': 'Private key not found'}), 404
    if not os.path.exists(full_chain_path):
        return jsonify({'error': 'Chain certificate file NOT found'}), 404
    try:
        stream = BytesIO()
        with ZipFile(stream, 'w') as zipf:
            zipf.write(full_path, arcname=filename) # add filename
            zipf.writestr(key_filename, key_content) # add private key
            zipf.write(full_chain_path, arcname=chain_filename)
        stream.seek(0)

        # delete key and csr after download
        key_path = os.path.join(certs_path, key_filename)
        print(key_path)
        # Delete the CSR file
        if os.path.exists(csr_file):
            os.remove(csr_file)

        if os.path.exists(key_path):
            os.remove(key_path)
        return send_file(
            stream, 
            as_attachment=True,
            download_name=f'{cert_id}.zip', 
            mimetype='application/zip'
        )
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({'error': 'File not found'}), 404

@app.route('/download_ca_certificate/<ca>', methods=['GET'])
def download_ca_certificate(ca):
    if ca == 'qubip-root-ca':
        filename = app.config['ROOT_CA_CERT']
    elif ca == 'qubip-tls-ca':
        filename = app.config['TLS_CA_CERT']
    elif ca == 'qubip-software-ca':
        filename = app.config['SOFTWARE_CA_CERT']
    if not os.path.exists(filename):
        logging.error(f"CA Certificate not found")
        return jsonify({'error': 'Certificate not found'}), 404
    try:
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({'error': 'File not found'}), 404


@app.route('/download_crl/<ca>', methods=['GET'])
def download_crl(ca):
    if ca == 'qubip-root-ca':
        ca_crl = app.config['ROOT_CA_CRL']
    elif ca == 'qubip-tls-ca':
        ca_crl = app.config['TLS_CA_CRL']
    elif ca == 'qubip-software-ca':
        ca_crl = app.config['SOFTWARE_CA_CRL']
    if not os.path.exists(ca_crl):
        return jsonify({'error': 'CRL not found'}), 404
    try:
        return send_file(ca_crl, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - CRL not found: %s", ca_crl)
        return jsonify({'error': 'File not found'}), 404

@app.route('/certificate_details/<ca>/ca_certificate', methods=['GET'])
def view_ca_certificate(ca):
    cert_id = ca
    if ca == 'qubip-root-ca':
        filename = app.config['ROOT_CA_CERT']
    elif ca == 'qubip-tls-ca':
        filename = app.config['TLS_CA_CERT']
    elif ca == 'qubip-software-ca':
        filename = app.config['SOFTWARE_CA_CERT']

    if not os.path.exists(filename):
        return jsonify({'error': 'Certificate not found'}), 404

    try:
        cert_data = get_ca_certificate_details(openssl, filename)
        return render_template('view-ca-certificate.html', 
                               cert_data=cert_data,
                               ca=ca)
    except Exception as e:
        logging.error(f"Error reading certificate: {e}")
        return jsonify({'error': 'Error reading certificate'}), 500

@app.route('/crl_details/<ca>/ca_crl', methods=['GET'])
def view_ca_crl(ca):
    cert_id = ca
    if ca == 'qubip-root-ca':
        filename = app.config['ROOT_CA_CRL']
    elif ca == 'qubip-tls-ca':
        filename = app.config['TLS_CA_CRL']
    elif ca == 'qubip-software-ca':
        filename = app.config['SOFTWARE_CA_CRL']

    logging.info(f"app.py - CRL filename: {filename}")
    if not os.path.exists(filename):
        return jsonify({'error': 'CRL not found'}), 404
    try:
        crl_data = get_crl_details(openssl, filename)
        return render_template('view-ca-crl.html', crl_data=crl_data, ca=ca)
    except Exception as e:
        return jsonify({'error': 'Error reading CRL'}), 500

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)