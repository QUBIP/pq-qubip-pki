from flask import Flask, request, render_template, jsonify, send_from_directory, url_for, send_file
import subprocess
import os
import uuid
import logging
import tempfile
from pkiCrypto import generate_private_key, generate_csr, sign_certificate, create_certificate_chain, get_ca_certificate_details, get_crl_details, convert_certificate_to_der
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
openssl = app.config['OPENSSL']

@app.route('/generate_certificate/<purpose>', methods=['GET','POST'])
def generate_certificate(purpose):
    if request.method == 'GET':
        return render_template('gen-cert.html', purpose=purpose)
    if request.method == 'POST':
        try:
            data = request.json or request.form
            device = data.get('device')
            if device == 'mpu':
                pki = 'pki-65'
                ca = app.config['MPU_CA']
                ca_certs_dir = os.path.join(app.config['PKI65_DIR'],'qubip-mpu-ca', 'newcerts')
                ca_conf = os.path.join(app.config['CONF_DIR_PKI65'], 'qubip-mpu-ca.conf')
                ca_key_file = os.path.join(app.config['PKI65_DIR'], 'qubip-mpu-ca', 'private', 'qubip-mpu-ca.key')
                ca_passfile = os.path.join(app.config['PKI65_DIR'], 'qubip-mpu-ca', 'private', '.qubip-mpu-ca-passphrase.txt')
                ca_cert = os.path.join(app.config['PKI65_DIR'], 'qubip-mpu-ca', 'qubip-mpu-ca-cert.pem')
                ca_chain = os.path.join(app.config['PKI65_DIR'], 'qubip-mpu-ca', 'qubip-mpu-ca-chain.pem')
                if purpose == 'server':
                    conf_file = os.path.join(app.config['CONF_DIR_PKI65'], 'qubip-server.conf')
                else:
                    conf_file = os.path.join(app.config['CONF_DIR_PKI65'], 'qubip-client.conf')
            elif device == 'mcu':
                pki = 'pki-44'
                ca = app.config['MCU_CA']
                ca_certs_dir = os.path.join(app.config['PKI44_DIR'],'qubip-mcu-ca', 'newcerts')
                ca_conf = os.path.join(app.config['CONF_DIR_PKI44'], 'qubip-mcu-ca.conf')
                ca_key_file = os.path.join(app.config['PKI44_DIR'], 'qubip-mcu-ca', 'private', 'qubip-mcu-ca.key')
                ca_passfile = os.path.join(app.config['PKI44_DIR'], 'qubip-mcu-ca', 'private', '.qubip-mcu-ca-passphrase.txt')
                ca_cert = os.path.join(app.config['PKI44_DIR'], 'qubip-mcu-ca', 'qubip-mcu-ca-cert.pem')
                ca_chain = os.path.join(app.config['PKI44_DIR'], 'qubip-mcu-ca', 'qubip-mcu-ca-chain.pem')
                if purpose == 'server':
                    conf_file = os.path.join(app.config['CONF_DIR_PKI44'], 'qubip-server.conf')
                else:
                    conf_file = os.path.join(app.config['CONF_DIR_PKI44'], 'qubip-client.conf')
            elif device == 'tls':
                pki = 'certs'
                ca = app.config['TLS_CA']
                ca_certs_dir = app.config['TLS_CERTS_DIR']
                ca_conf = app.config['TLS_CA_CONF']
                ca_key_file = app.config['TLS_CA_KEY']
                ca_passfile = app.config['TLS_CA_PASSWORD']
                ca_cert = app.config['TLS_CA_CERT']
                ca_chain = app.config['TLS_CA_CHAIN']
                if purpose == 'server':
                    conf_file = app.config['SERVER_CONF']
                else:
                    conf_file = app.config['CLIENT_CONF']
            logging.info(data)
            algorithm = data.get('algorithm') 
            logging.debug(f"Using algorithm: {algorithm}")

            commonName = data.get('common_name')
            cn_type = data.get('cn_type') # IP/DNS
            cert_id = f'{str(uuid.uuid4().hex[:10 ])}-{purpose}' 

            if not os.path.exists(app.config['TEMP_KEY_DIR']):
                os.makedirs(app.config['TEMP_KEY_DIR'])
            key_file = os.path.join(app.config['TEMP_KEY_DIR'], f'{cert_id}.key')
            logging.debug(f"Key file: {key_file}")
            logging.debug(f"Generating certificate for {purpose} with commonName: {commonName}, algorithm: {algorithm}, cert_id: {cert_id}")
            generate_private_key(openssl, key_file, algorithm)
            if not key_file:
                return {"error": "Failed to generate private key"}, 500
            else:
                logging.info("PRIVATE KEY GENERATED")
                logging.info(f"Key file: {key_file}")
                subjectAltName = commonName
                logging.info(f"SAN = {subjectAltName}")
                subj = f"/C=EU/O=QUBIP/CN={commonName}"
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
                    convert_certificate_to_der(openssl, cert_file)
                    logging.info("DER certificate converted")
                    create_certificate_chain(cert_file, ca_chain, chain_path)
                    convert_certificate_to_der(openssl, chain_path)
                    logging.info(chain_path)
                    
                    return jsonify({
                        'pki': pki,
                        'ca': ca,
                        'certificate_id': cert_id,
                        'certificate': certificate,
                        'filename': f'{cert_id}.pem'
                        }), 200
        except Exception as e:
            logging.error(f"Error generating certificate: {e}")
            return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 400

@app.route('/download_certificate/<pki>/<ca>/<cert_id>', methods=['GET'])
def download_certificate(pki, ca, cert_id):
    logging.info(pki)
    if pki == 'pki-65':
        working_dir = app.config['PKI65_DIR']
    elif pki == 'pki-44':
        working_dir = app.config['PKI44_DIR']
    elif pki == 'certs':
        working_dir = app.config['CERTS_DIR']
    else:
        return jsonify({'error': f'Invalid PKI: {pki}'}), 400  # <--- ADD THIS
    logging.info(working_dir)
    logging.info(ca)
    logging.info(cert_id)
    filename = f'{cert_id}-cert.pem'
    csr_file = f'{cert_id}.csr'
    chain_filename = f'{cert_id}-chain.pem'
    if ca == 'qubip-mpu-ca':
        certs_path = os.path.join(working_dir, 'qubip-mpu-ca', 'newcerts')
    elif ca == 'qubip-mcu-ca':
        certs_path = os.path.join(working_dir, 'qubip-mcu-ca', 'newcerts')
    elif ca == 'qubip-tls-ca':
        certs_path = os.path.join(working_dir, 'qubip-tls-ca', 'newcerts')
    else:
        return jsonify({'error': 'CA not found'}), 404

    full_path = os.path.join(certs_path, filename) 
    der_cert = os.path.join(certs_path, f'{filename}.der')
    if not os.path.exists(der_cert):
        logging.error(f"DER certificate not found: {der_cert}")
        return jsonify({'error': 'DER certificate not found'}), 404
    
    full_chain_path = os.path.join(certs_path, chain_filename) 
    der_chain = f'{full_chain_path}.der'
    if not os.path.exists(full_path):
        return jsonify({'error': 'Certificate not found'}), 404
    if not os.path.exists(der_chain):
        logging.error(f"DER chain certificate not found: {der_chain}")
        return jsonify({'error': 'DER chain certificate not found'}), 404
    logging.info(der_chain)
    key_filename = os.path.join(app.config['TEMP_KEY_DIR'], f"{cert_id}.key")
    if not os.path.exists(key_filename):
        return jsonify({'error': 'Private key not found'}), 404
    if not os.path.exists(full_chain_path):
        return jsonify({'error': 'Chain certificate file NOT found'}), 404
    with open(key_filename, 'r') as f:
        key_content = f.read()
    try:
        stream = BytesIO()
        with ZipFile(stream, 'w') as zipf:
            zipf.write(full_path, arcname=filename) # add filename
            zipf.write(der_cert, arcname=f'{cert_id}-cert.der') # add der cert
            #zipf.write(der_chain, arcname=f'{cert_id}-chain.der') # add der chain
            zipf.writestr(key_filename, key_content) # add private key
            zipf.write(full_chain_path, arcname=chain_filename)
        stream.seek(0)

        # delete key and csr after download
        os.remove(key_filename)
        # Delete the CSR file
        if os.path.exists(csr_file):
            os.remove(csr_file)
        return send_file(
            stream, 
            as_attachment=True,
            download_name=f'{cert_id}.zip', 
            mimetype='application/zip'
        )
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({'error': 'File not found'}), 404

@app.route('/<chain>/<ca>/certificate', methods=['GET'])
def download_ca_certificate(chain, ca):
    if chain == 'certs':
        certs_path = app.config['CERTS_DIR']
    elif chain == 'pki-65':
        certs_path = app.config['PKI65_DIR']
    elif chain == 'pki-44':
        certs_path = app.config['PKI44_DIR']
    if ca == 'qubip-root-ca':
        filename = os.path.join(certs_path, app.config['ROOT_CA'],'qubip-root-ca-cert.pem')
    elif ca == 'qubip-mpu-ca':
        filename = os.path.join(certs_path, app.config['MPU_CA'],'qubip-mpu-ca-cert.pem')
    elif ca == 'qubip-mcu-ca':
        filename = os.path.join(certs_path, app.config['MCU_CA'],'qubip-mcu-ca-cert.pem')
    elif ca == 'qubip-tls-ca':
        filename = app.config['TLS_CA_CERT']
    if not os.path.exists(filename):
        logging.error(f"CA Certificate not found")
        return jsonify({'error': 'Certificate not found'}), 404
    try:
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({'error': 'File not found'}), 404


@app.route('/download_crl/<chain>/<ca>', methods=['GET'])
def download_crl(chain, ca):
    if chain == 'certs':
        working_dir = app.config['CERTS_DIR']
    elif chain == 'pki-65':
        working_dir = app.config['PKI65_DIR']
    elif chain == 'pki-44':
        working_dir = app.config['PKI44_DIR']
    
    if ca == 'qubip-root-ca':
        ca_crl = os.path.join(working_dir, app.config['ROOT_CA'],'crl','qubip-root-ca.crl')
    elif ca == 'qubip-mpu-ca':
        ca_crl = os.path.join(working_dir, app.config['MPU_CA'],'crl','qubip-mpu-ca.crl')
    elif ca == 'qubip-mcu-ca':
        ca_crl = os.path.join(working_dir, app.config['MCU_CA'],'crl','qubip-mcu-ca.crl')
    elif ca == 'qubip-tls-ca':
        ca_crl = app.config['TLS_CA_CRL']
    if not os.path.exists(ca_crl):
        return jsonify({'error': 'CRL not found'}), 404
    try:
        return send_file(ca_crl, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - CRL not found: %s", ca_crl)
        return jsonify({'error': 'File not found'}), 404

@app.route('/certificate_details/<chain>/<ca>/ca_certificate', methods=['GET'])
def view_ca_certificate(chain, ca):
    if chain == 'certs':
        certs_path = app.config['CERTS_DIR']
    elif chain == 'pki-65':
        certs_path = app.config['PKI65_DIR']
    elif chain == 'pki-44':
        certs_path = app.config['PKI44_DIR']
    
    cert_id = ca
    if ca == 'qubip-root-ca':
        filename = os.path.join(certs_path, app.config['ROOT_CA'],'qubip-root-ca-cert.pem')
    elif ca == 'qubip-mpu-ca':
        filename = os.path.join(certs_path, app.config['MPU_CA'],'qubip-mpu-ca-cert.pem')
    elif ca == 'qubip-mcu-ca':
        filename = os.path.join(certs_path, app.config['MCU_CA'],'qubip-mcu-ca-cert.pem')
    elif ca == 'qubip-tls-ca':
        filename = os.path.join(certs_path, app.config['TLS_CA'],'qubip-tls-ca-cert.pem')

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

@app.route('/crl_details/<chain>/<ca>', methods=['GET'])
def view_ca_crl(chain, ca):
    cert_id = ca
    logging.info(chain)
    if chain == 'certs':
        working_dir = app.config['CERTS_DIR']
    elif chain == 'pki-65':
        working_dir = app.config['PKI65_DIR']
    elif chain == 'pki-44':
        working_dir = app.config['PKI44_DIR']
    if ca == 'qubip-root-ca':
        filename = os.path.join(working_dir, app.config['ROOT_CA'],'crl','qubip-root-ca.crl')
    elif ca == 'qubip-mpu-ca':
        filename = os.path.join(working_dir, app.config['MPU_CA'],'crl','qubip-mpu-ca.crl')
    elif ca == 'qubip-mcu-ca':
        filename = os.path.join(working_dir, app.config['MCU_CA'],'crl','qubip-mcu-ca.crl')
    elif ca == 'qubip-tls-ca':
        filename = app.config['TLS_CA_CRL']

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
    app.run(host='130.192.1.31', debug=True, port=5000)