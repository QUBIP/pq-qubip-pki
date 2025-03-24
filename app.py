from flask import Flask, request, render_template, jsonify, send_from_directory, url_for, send_file
import subprocess
import os
import uuid
import logging
import tempfile
from pkiCrypto import generate_private_key, generate_csr, sign_certificate, create_certificate_chain, retrieve_ca_info, get_ca_certificate_details, get_crl_details
from io import BytesIO # allows to create files without saving them on disk (useful for private key)
from zipfile import ZipFile 
from cryptography import x509
import base64
from cryptography.hazmat.backends import default_backend
from config import Config
import ssl

# Setup logging
logging.basicConfig(level=logging.DEBUG)

# Initialize flask app
app = Flask(__name__, static_url_path='/static')

# Load configurations
app.config.from_object(Config)

# Validate configurations
Config.validate()
private_keys = {}  # Store private keys in memory

@app.route('/generate_certificate/<purpose>', methods=['GET','POST'])
def generate_certificate(purpose):
    
    if request.method == 'GET':
        return render_template('generate_certificate.html', purpose=purpose)
    if request.method == 'POST':
        try:
            data = request.json or request.form
            if purpose == 'tls-server' or purpose == 'tls-client':
                ca = app.config['TLS_CA']
                ca_certs_dir = app.config['TLS_CERTS_DIR']
                if purpose == 'tls-server':
                    conf_file = app.config['TLS_SERVER_CONF']
                else:
                    conf_file = app.config['TLS_CLIENT_CONF']
            elif purpose == 'code-signing':
                ca = app.config['SOFTWARE_CA']
                ca_certs_dir = app.config['SOFTWARE_CERTS_DIR']
                conf_file = app.config['CODESIGN_CONF']
            
            # Get the certificate details
            algorithm = data.get('algorithm') 
            commonName = data.get('commonName')
            cn_type = data.get('cn_type') # IP/DNS/Email

            # Generate a unique certificate ID
            cert_id = f'{str(uuid.uuid4().hex[:10 ])}-{purpose}' 

            # Generate the private key, CSR, and certificate
            key_file, csr_file, cert_file, ca_key, ca_passfile, ca_cert, ca_conf, ca_chain = retrieve_ca_info(app.config, ca, cert_id)
            generate_private_key(key_file, algorithm)
            if not key_file:
                return {"error": "Failed to generate private key"}, 500
            else:
                # Store private key in memory (for temporary access)
                with open(key_file, 'r') as key_fp:
                    private_keys[cert_id] = key_fp.read()
                # create subject material for csr and certificate
                key_fp.close()

                # create subject material for csr and certificate
                subjectAltName = ""
                if purpose != "code-signing":
                    subjectAltName = commonName
                    subj = f"/C=EU/O=QUBIP/CN={commonName}"
                else:
                    subj = f"/C=EU/O=QUBIP/CN={commonName}/userId={cert_id}"

                # Generate the CSR 
                generate_csr(key_file,csr_file, subj, conf_file, commonName, subjectAltName, cn_type)
                if not csr_file:
                    return jsonify({"error": "Failed to generate CSR"}), 500

                # Sign the certificate with CA key
                cert_file = sign_certificate(csr_file, cert_file, purpose, ca_key, ca_passfile, ca_cert, ca_conf)

                # Delete the CSR file
                if os.path.exists(csr_file):
                    os.remove(csr_file)
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

    # Check if the certificate file exists
    if not os.path.exists(filename):
        return jsonify({'error': 'Certificate not found'}), 404

    # Read and return the certificate content
    try:
        cert_data = get_ca_certificate_details(filename)
        return render_template('view_ca_certificate.html', 
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

    # Read and return the CRL content
    try:
        crl_data = get_crl_details(filename)
        return render_template('view_ca_crl.html', crl_data=crl_data, ca=ca)
    except Exception as e:
        return jsonify({'error': 'Error reading CRL'}), 500

APP_CERT = app.config['APP_CERT']
APP_KEY = app.config['APP_KEY']
APP_CA_CERT = app.config['APP_CA_CERT']
CHAIN = app.config['APP_CHAIN']
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile=CHAIN, keyfile=APP_KEY, password=None)
# Home page
@app.route('/')
def home():
    # home_url = url_for('home')
    # logging.info("app.py - HOME URL: ", home_url)
    return render_template('home.html')  # Render the new home page template
if __name__ == '__main__':
    logging.info("app.py - Starting Flask application with HTTPS...")
    app.run(debug=True, host='127.0.0.1', port=5000, ssl_context=ssl_context)