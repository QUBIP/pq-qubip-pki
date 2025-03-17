from flask import Flask, request, render_template, jsonify, send_from_directory, url_for, send_file
import subprocess
import os
import uuid
import logging
import tempfile
import pkiCrypto
from io import BytesIO # allows to create files without saving them on disk (useful for private key)
from zipfile import ZipFile 
from security import directories
from cryptography import x509
import base64
from cryptography.hazmat.backends import default_backend
from config import Config


# Setup logging
logging.basicConfig(level=logging.DEBUG)

# Initialize flask app
app = Flask(__name__, static_url_path='/static')

os.makedirs(directories.CERTS_DIR, exist_ok=True)

@app.route('/generate_certificate/<purpose>', methods=['GET','POST'])
def generate_certificate(purpose):
    
    logging.debug("app.py - Received request to generate certificate.")
    if request.method == 'GET':
        return render_template('generate_certificate.html', purpose=purpose)
    if request.method == 'POST':
        try:
            logging.debug("app.py - Received request to generate private key.")
            data = request.json or request.form
            if purpose == 'tls-server' or purpose == 'tls-client':
                ca = 'qubip-tls-ca'
                ca_certs_dir = directories.TLS_CERTS_DIR
                if purpose == 'tls-server':
                    conf_file = directories.TLS_SERVER_CONF
                else:
                    conf_file = directories.TLS_CLIENT_CONF
            elif purpose == 'code-signing':
                ca = 'qubip-software-ca'
                ca_certs_dir = directories.SOFTWARE_CERTS_DIR
                conf_file = directories.CODESIGN_CONF
            
            logging.debug("app.py - Selected CA: %s", ca)
            algorithm = data.get('algorithm') 
            commonName = data.get('commonName')
            cn_type = data.get('cn_type')
            cert_id = f'{str(uuid.uuid4())}-{purpose}'
            logging.info("app.py - Generating certificate with ID: %s", cert_id)
            key_file, csr_file, cert_file, ca_key, ca_passfile, ca_cert, ca_conf, ca_chain = pkiCrypto.retrieve_ca_info(ca, cert_id)

            pkiCrypto.generate_private_key(key_file, algorithm)
            logging.debug("app.py - Generated private key: %s", key_file)
            if key_file:
                # Store private key in memory (for temporary access)
                with open(key_file, 'r') as key_fp:
                    private_keys[cert_id] = key_fp.read()
                # create subject material for csr and certificate
                key_fp.close()
                #logging.debug(private_keys)
                subjectAltName = ""
                if purpose != "code-signing":
                    subjectAltName = commonName
                    subj = f"/C=EU/O=QUBIP/CN={commonName}"
                else:
                    subj = f"/C=EU/O=QUBIP/CN={commonName}/userId={cert_id}"
                    
                
                logging.debug(commonName)
                logging.debug(purpose)
                logging.debug(subjectAltName)
                pkiCrypto.generate_csr(key_file,csr_file, subj, conf_file, commonName, subjectAltName, cn_type)
                logging.debug("app.py - Generated CSR: %s", csr_file)
                if not csr_file:
                    return jsonify({"error": "Failed to generate CSR"}), 500
                cert_file = pkiCrypto.sign_certificate(csr_file, cert_file, purpose, ca_key, ca_passfile, ca_cert, ca_conf)
                logging.debug("app.py - Generated certificate: %s", cert_file)
                if os.path.exists(csr_file):
                    os.remove(csr_file)
                    logging.debug("app.py - Deleted CSR: %s", csr_file)
                with open(cert_file, 'r') as cert_fp:
                    certificate = cert_fp.read()
                logging.info("app.py - Certificate generation successful for ID: %s", cert_id)
                if cert_file:
                    # pkiCrypto.convert_certificate_to_der(cert_file)
                    # logging.debug("app.py - Converted certificate to DER format")
                    chain_file = f'{cert_id}-chain.pem'
                    chain_path = os.path.join(ca_certs_dir, chain_file)
                    pkiCrypto.create_certificate_chain(cert_file, ca_chain, chain_path)
                    logging.debug("app.py - Created certificate chain: %s", chain_path)

                    certificate_data = {
                        'ca': ca,
                        'certificate_id': cert_id,
                        #'certificate': certificate,
                        'filename': f'{cert_id}.pem'  # Return the filename for downloading
                     }
                    app.config[f"CERT_{cert_id}"] = certificate_data  # Store in app.config
                    return jsonify({
                        'ca': ca,
                        'certificate_id': cert_id,
                        'certificate': certificate,
                        'redirect_url': url_for('view_certificate', ca=ca, cert_id=cert_id),
                        'filename': f'{cert_id}.pem'
                        }), 200
                else:
                    return jsonify({"error": "Failed to generate certificate"}), 500
            else:
                return {"error": "Failed to generate private key"}, 500
        except Exception as e:
            logging.error("app.py - Unexpected error: %s", str(e))
            return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 400

@app.route('/download_certificate/<ca>/<cert_id>', methods=['GET'])
def download_certificate(ca, cert_id):
    filename = f'{cert_id}-cert.pem'
    chain_filename = f'{cert_id}-chain.pem'
    logging.debug("app.py - Received request to download certificate: %s", cert_id)
    certs_path = os.path.join(os.getcwd(), "certs", ca, "newcerts") 
    if os.path.exists(certs_path):
        logging.debug("app.py - Certs path: %s", certs_path)
    else:
        logging.error("app.py - Certs path not found: %s", certs_path)

    full_path = os.path.join(certs_path, filename) 
    full_chain_path = os.path.join(certs_path, chain_filename) 
    logging.debug("app.py - Certificate path: %s", full_path)
    if os.path.exists(full_path):
        logging.debug("app.py - Certificate found: %s", full_path)
    else:
        logging.error("app.py - Certificate not found: %s", full_path)
        return jsonify({'error': 'Certificate not found'}), 404
    key_filename = f'{cert_id}.key'
    #logging.debug("app.py - Private keys: %s", key_filename)
    #logging.debug(private_keys)
    key_content = private_keys.pop(cert_id, None)  # Retrieve and remove the private key from memory
    #logging.debug(key_content)
    if  key_content:
        logging.debug(f"Private key  found for ID: %s", cert_id)
    else:
        logging.error(f"Private key not found for ID: %s", cert_id)
        return jsonify({'error': 'Private key not found'}), 404
    if not os.path.exists(full_chain_path):
        logging.error("app.py - Chain certificate file NOT found: %s", full_chain_path)
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
            logging.debug("app.py - Deleted private key: %s", key_path)
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
    filename = f'{ca}-cert.pem'
    logging.debug("app.py - Received request to download CA certificate: %s", ca)
    certs_path = os.path.join(os.getcwd(), "certs", ca)  
    full_path = os.path.join(certs_path, filename)  
    logging.debug("app.py - Certificate path: %s", full_path)
    if not os.path.exists(full_path):
        logging.error(f"CA Certificate not found")
        return jsonify({'error': 'Certificate not found'}), 404
    try:
        return send_from_directory(certs_path, filename, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({'error': 'File not found'}), 404

@app.route('/<ca>/download_chain/<cert_id>', methods=['GET'])
def download_ca_chain(ca, cert_id):
    filename = f'{cert_id}-chain.pem.der'
    logging.debug("app.py - Received request to download Certificate chain: %s", ca)
    certs_path = os.path.join(os.getcwd(), "certs", ca, "newcerts")  
    full_path = os.path.join(certs_path, filename)  
    logging.debug("app.py - Certificate chain path: %s", full_path)
    if not os.path.exists(full_path):
        logging.error(f"CA Certificate chain not found")
        return jsonify({'error': 'Certificate chain not found'}), 404
    try:
        return send_from_directory(certs_path, filename, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - Certificate chain not found: %s", filename)
        return jsonify({'error': 'File not found'}), 404


@app.route('/download_crl/<ca>', methods=['GET'])
def download_crl(ca):
    ca_crl=f'{ca}.crl'
    logging.debug("app.py - Received request to download CA CRL: %s", ca_crl)
    certs_path = os.path.join(os.getcwd(), "certs", ca, "crl")  
    full_path = os.path.join(certs_path, ca_crl)  
    logging.debug("app.py - Certificate path: %s", full_path)
    if not os.path.exists(full_path):
        logging.error(f"CA CRL not found")
        return jsonify({'error': 'CRL not found'}), 404
    try:
        return send_from_directory(certs_path, ca_crl, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - CRL not found: %s", ca_crl)
        return jsonify({'error': 'File not found'}), 404

@app.route('/certificate_details/<ca>/ca_certificate', methods=['GET'])
def view_ca_certificate(ca):
    logging.debug(ca)
    cert_id = ca
    filename = f'{cert_id}-cert.pem'
    chain_path = f'{cert_id}-chain.pem.der'
    certs_path = os.path.join(os.getcwd(), "certs", ca)  
    full_path = os.path.join(certs_path, filename)  
    logging.debug("app.py - Certificate path: %s", full_path)

    # Check if the certificate file exists
    if not os.path.exists(full_path):
        logging.error("Certificate not found: %s", filename)
        return jsonify({'error': 'Certificate not found'}), 404
    else:
        logging.debug("Certificate found: %s", filename)

    # Read and return the certificate content
    try:
        cert_data = pkiCrypto.get_ca_certificate_details(full_path)
        return render_template('view_ca_certificate.html', 
                               cert_data=cert_data,
                               ca=ca)
    except Exception as e:
        logging.error(f"Error reading certificate: {e}")
        return jsonify({'error': 'Error reading certificate'}), 500

@app.route('/crl_details/<ca>/ca_crl', methods=['GET'])
def view_ca_crl(ca):
    logging.debug(ca)
    cert_id = ca
    filename = f'{ca}.crl'
    certs_path = os.path.join(os.getcwd(), "certs", ca, "crl")  
    full_path = os.path.join(certs_path, filename)  
    logging.debug("app.py - CRL path: %s", full_path)

    # Check if the CRL file exists
    if not os.path.exists(full_path):
        logging.error("CRL not found: %s", filename)
        return jsonify({'error': 'CRL not found'}), 404
    else:
        logging.debug("CRL found: %s", filename)

    # Read and return the CRL content
    try:
        with open(full_path, 'r') as crl_file:
            crl_data = crl_file.read()
        crl_file.close()
        crl_data = pkiCrypto.get_crl_details(full_path)
        return render_template('view_ca_crl.html', crl_data=crl_data, ca=ca)
    except Exception as e:
        logging.error(f"Error reading CRL: {e}")
        return jsonify({'error': 'Error reading CRL'}), 500
    # Read and return the CRL content
    # try:
    #     ca_crl = f'{ca}.crl'
    #     logging.debug("app.py - CA CRL: %s", ca_crl)
    #     logging.debug("app.py - CRL details: %s", crl_data)
    #     return render_template('view_ca_crl.html',
    #                            ca=ca)
    # except Exception as e:
    #     logging.error(f"Error reading CRL: {e}")
    #     return jsonify({'error': 'Error reading CRL'}), 500

@app.route('/certificate_details/<ca>/<cert_id>', methods=['GET'])
def view_certificate(ca, cert_id):
    filename = f'{cert_id}.pem'
    chain_path = f'{cert_id}-chain.pem.der'
    logging.debug("app.py - Received request to view certificate: %s", cert_id)
    certs_path = os.path.join(os.getcwd(), "certs", ca, "newcerts")  
    full_path = os.path.join(certs_path, filename)  
    logging.debug("app.py - Certificate path: %s", full_path)

    # Check if the certificate file exists
    if not os.path.exists(full_path):
        logging.error("Certificate not found: %s", filename)
        return jsonify({'error': 'Certificate not found'}), 404

    # Read and return the certificate content
    try:
        cert_data = pkiCrypto.get_certificate_details(cert_id, full_path, chain_path)
        ca_crl = f'{ca}.crl'
        logging.debug("app.py - CA CRL: %s", ca_crl)
        logging.debug("app.py - Certificate details: %s", cert_data)
        return render_template('certificate_details.html', 
                               cert_data=cert_data,
                               ca=ca,
                               ca_crl=ca_crl)
    except Exception as e:
        logging.error(f"Error reading certificate: {e}")
        return jsonify({'error': 'Error reading certificate'}), 500


# Home page
@app.route('/')
def home():
    return render_template('home.html')  # Render the new home page template

if __name__ == '__main__':
    logging.info("app.py - Starting Flask application...")

    with app.app_context():
        home_url = url_for('pki.all.qubip.eu')
        logging.info("app.py - HOME URL: ", home_url)
        
    app.run(debug=True)
    