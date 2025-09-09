from flask import Flask, request, abort, render_template, jsonify, send_file
import os
import shutil
import tempfile
import uuid
import logging
from io import BytesIO
from zipfile import ZipFile
from werkzeug.utils import secure_filename

from pkiCrypto import (
    generate_private_key,
    generate_csr,
    sign_certificate,
    create_certificate_chain,
    get_ca_certificate_details,
    get_crl_details,
    convert_certificate_to_der,
)
from config import Config

# -----------------------------------------------------------------------------
# App & config
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)

app = Flask(__name__, static_url_path="/static")
app.config.from_object(Config)
Config.validate()

openssl = app.config["OPENSSL"]
OQS_CONF = "/opt/pki-file/oqs.cnf"


# -----------------------------------------------------------------------------
# Small utilities (no logic changes, just helpers)
# -----------------------------------------------------------------------------
def _abort_if_missing(path: str, msg: str):
    if not os.path.exists(path):
        logging.error(msg)
        abort(404, msg)

def _tmpdir(prefix: str) -> str:
    return tempfile.mkdtemp(prefix=prefix)

def _safe_name(name: str, fallback: str) -> str:
    return secure_filename(name) or fallback

# -----------------------------------------------------------------------------
# Path mappers (centralize all directory/file names; logic unchanged)
# -----------------------------------------------------------------------------
def chain_issue_paths(chain: str):
    """Paths needed by /issue_from_csr based on chain."""
    if chain == "pki-65":
        base = app.config["PKI65_DIR"]
        ca_name = "qubip-mpu-ca"
        return {
            "ca_certs_dir": os.path.join(base, ca_name, "newcerts"),
            "ca_conf":      os.path.join(app.config["CONF_DIR_PKI65"], f"{ca_name}.conf"),
            "ca_key_file":  os.path.join(base, ca_name, "private", f"{ca_name}.key"),
            "ca_passfile":  os.path.join(base, ca_name, "private", f".{ca_name}-passphrase.txt"),
            "ca_cert":      os.path.join(base, ca_name, f"{ca_name}-cert.pem"),
            "ca_chain":     os.path.join(base, ca_name, f"{ca_name}-chain.pem"),
        }
    if chain == "pki-44":
        base = app.config["PKI44_DIR"]
        ca_name = "qubip-mcu-ca"
        return {
            "ca_certs_dir": os.path.join(base, ca_name, "newcerts"),
            "ca_conf":      os.path.join(app.config["CONF_DIR_PKI44"], f"{ca_name}.conf"),
            "ca_key_file":  os.path.join(base, ca_name, "private", f"{ca_name}.key"),
            "ca_passfile":  os.path.join(base, ca_name, "private", f".{ca_name}-passphrase.txt"),
            "ca_cert":      os.path.join(base, ca_name, f"{ca_name}-cert.pem"),
            "ca_chain":     os.path.join(base, ca_name, f"{ca_name}-chain.pem"),
        }
    if chain == "certs":
        return {
            "ca_certs_dir": app.config["TLS_CERTS_DIR"],
            "ca_conf":      app.config["TLS_CA_CONF"],
            "ca_key_file":  app.config["TLS_CA_KEY"],
            "ca_passfile":  app.config["TLS_CA_PASSWORD"],
            "ca_cert":      app.config["TLS_CA_CERT"],
            "ca_chain":     app.config["TLS_CA_CHAIN"],
        }
    abort(400, "Invalid chain")

def device_ctx(device: str, purpose: str):
    """
    Paths & config needed by /generate_certificate based on device + purpose.
    (Same logic; just centralized.)
    """
    if device == "mpu":
        pki = "pki-65"
        ca_name = "qubip-mpu-ca"
        base = app.config["PKI65_DIR"]
        conf_dir = app.config["CONF_DIR_PKI65"]
        conf_file = os.path.join(conf_dir, "qubip-server.conf" if purpose == "server" else "qubip-client.conf")
        return {
            "pki": pki,
            "ca": app.config["MPU_CA"],
            "ca_certs_dir": os.path.join(base, ca_name, "newcerts"),
            "ca_conf":      os.path.join(conf_dir, f"{ca_name}.conf"),
            "ca_key_file":  os.path.join(base, ca_name, "private", f"{ca_name}.key"),
            "ca_passfile":  os.path.join(base, ca_name, "private", f".{ca_name}-passphrase.txt"),
            "ca_cert":      os.path.join(base, ca_name, f"{ca_name}-cert.pem"),
            "ca_chain":     os.path.join(base, ca_name, f"{ca_name}-chain.pem"),
            "conf_file":    conf_file,
        }
    if device == "mcu":
        pki = "pki-44"
        ca_name = "qubip-mcu-ca"
        base = app.config["PKI44_DIR"]
        conf_dir = app.config["CONF_DIR_PKI44"]
        conf_file = os.path.join(conf_dir, "qubip-server.conf" if purpose == "server" else "qubip-client.conf")
        return {
            "pki": pki,
            "ca": app.config["MCU_CA"],
            "ca_certs_dir": os.path.join(base, ca_name, "newcerts"),
            "ca_conf":      os.path.join(conf_dir, f"{ca_name}.conf"),
            "ca_key_file":  os.path.join(base, ca_name, "private", f"{ca_name}.key"),
            "ca_passfile":  os.path.join(base, ca_name, "private", f".{ca_name}-passphrase.txt"),
            "ca_cert":      os.path.join(base, ca_name, f"{ca_name}-cert.pem"),
            "ca_chain":     os.path.join(base, ca_name, f"{ca_name}-chain.pem"),
            "conf_file":    conf_file,
        }
    if device == "tls":
        pki = "certs"
        conf_file = app.config["SERVER_CONF"] if purpose == "server" else app.config["CLIENT_CONF"]
        return {
            "pki": pki,
            "ca": app.config["TLS_CA"],
            "ca_certs_dir": app.config["TLS_CERTS_DIR"],
            "ca_conf":      app.config["TLS_CA_CONF"],
            "ca_key_file":  app.config["TLS_CA_KEY"],
            "ca_passfile":  app.config["TLS_CA_PASSWORD"],
            "ca_cert":      app.config["TLS_CA_CERT"],
            "ca_chain":     app.config["TLS_CA_CHAIN"],
            "conf_file":    conf_file,
        }
    abort(400, f"Invalid device: {device}")

def chain_base_dir(chain: str) -> str:
    if chain == "certs":
        return app.config["CERTS_DIR"]
    if chain == "pki-65":
        return app.config["PKI65_DIR"]
    if chain == "pki-44":
        return app.config["PKI44_DIR"]
    abort(400, "Invalid chain")

def ca_cert_path(chain: str, ca: str) -> str:
    base = chain_base_dir(chain)
    if ca == "qubip-root-ca":
        return os.path.join(base, app.config["ROOT_CA"], "qubip-root-ca-cert.pem")
    if ca == "qubip-mpu-ca":
        return os.path.join(base, app.config["MPU_CA"], "qubip-mpu-ca-cert.pem")
    if ca == "qubip-mcu-ca":
        return os.path.join(base, app.config["MCU_CA"], "qubip-mcu-ca-cert.pem")
    if ca == "qubip-tls-ca":
        return app.config["TLS_CA_CERT"]
    abort(404, "CA not found")

def ca_crl_path(chain: str, ca: str) -> str:
    base = chain_base_dir(chain)
    if ca == "qubip-root-ca":
        return os.path.join(base, app.config["ROOT_CA"], "crl", "qubip-root-ca.crl")
    if ca == "qubip-mpu-ca":
        return os.path.join(base, app.config["MPU_CA"], "crl", "qubip-mpu-ca.crl")
    if ca == "qubip-mcu-ca":
        return os.path.join(base, app.config["MCU_CA"], "crl", "qubip-mcu-ca.crl")
    if ca == "qubip-tls-ca":
        return app.config["TLS_CA_CRL"]
    abort(404, "CA not found")

def issued_certs_dir_for(pki: str, ca: str) -> str:
    base = chain_base_dir(pki)
    if ca == "qubip-mpu-ca":
        return os.path.join(base, "qubip-mpu-ca", "newcerts")
    if ca == "qubip-mcu-ca":
        return os.path.join(base, "qubip-mcu-ca", "newcerts")
    if ca == "qubip-tls-ca":
        return os.path.join(base, "qubip-tls-ca", "newcerts")
    abort(404, "CA not found")

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post('/issue_from_csr')
def issue_from_csr():
    # read form fields
    chain = request.form.get("chain", "").strip()
    purpose = request.form.get("purpose", "").strip()
    out_format = request.form.get("out_format", "pem").strip().lower()
    include_chain = "include_chain" in request.form # checkbox
    paths = chain_issue_paths(chain)

    if purpose not in {"server", "client"}:
        abort(400, "Invalid purpose")
    if out_format not in {"pem", "der"}:
        abort(400, "Invalid output format")

    up = request.files.get("csr")
    if not up or up.filename == "":
        abort(400, "CSR file is required")
    # 3) Work in an isolated temp dir
    workdir = tempfile.mkdtemp(prefix="csr_issue_")
    try:
        csr_path = os.path.join("/tmp/", "input.csr")
        up.save(csr_path)
        logging.info(csr_path)

        # 4) Issue certificate (always produce PEM first)
        leaf_pem = os.path.join(workdir, f"{purpose}.pem")
        sign_certificate(
            openssl, chain, csr_path, leaf_pem, purpose,
            paths["ca_key_file"], paths["ca_passfile"], paths["ca_cert"], paths["ca_conf"],
        )
        # 5) Optionally build bundle
        download_path = leaf_pem
        download_name = f"leaf-{purpose}-{chain}.pem"
        if include_chain:
            bundle_pem = os.path.join(workdir, "bundle.pem")
            create_certificate_chain(leaf_pem, paths['ca_chain'], bundle_pem)
            download_path = bundle_pem
            download_name = f"leaf_bundle-{purpose}-{chain}.pem"

        # 6) Convert to DER if requested
        if out_format == "der":
            der_path = os.path.join(workdir, "leaf.der")
            # If bundle was requested with DER, you likely still return leaf.der (bundling DER is uncommon).
            convert_certificate_to_der(openssl, chain, leaf_pem)
            download_path = der_path
            download_name = download_name.replace(".pem", ".der")

        # 7) Return file as download
        mimetype = "application/pkix-cert" if out_format == "der" else "application/x-pem-file"
        return send_file(download_path, as_attachment=True, download_name=download_name, mimetype=mimetype)

    except Exception as e:
        app.logger.exception("Issuance failed")
        return jsonify({"error": str(e)}), 500
    finally:
        # Remove temp dir after response has been sent
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass


@app.route('/generate_certificate/<purpose>', methods=['GET','POST'])
def generate_certificate(purpose):
    if request.method == 'GET':
        return render_template('gen-cert.html', purpose=purpose)
    if request.method == 'POST':
        try:
            data = request.json or request.form
            device = data.get('device')
            ctx = device_ctx(device, purpose)
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
            generate_private_key(openssl, ctx['pki'], key_file, algorithm)
            if not key_file:
                return {"error": "Failed to generate private key"}, 500
            else:
                logging.info("PRIVATE KEY GENERATED")
                logging.info(f"Key file: {key_file}")
                subjectAltName = commonName
                logging.info(f"SAN = {subjectAltName}")
                subj = f"/C=EU/O=QUBIP/CN={commonName}"
                csr_file = os.path.join(ctx['ca_certs_dir'], f'{cert_id}.csr')
                generate_csr(
                    openssl, ctx["pki"], key_file, csr_file, subj, ctx["conf_file"],
                    commonName, subjectAltName, cn_type
                )          
                if not csr_file:
                    return jsonify({"error": "Failed to generate CSR"}), 500
                logging.info("CSR GENERATED")
                cert_file = os.path.join(ctx['ca_certs_dir'], f'{cert_id}-cert.pem')
                sign_certificate(
                    openssl, ctx["pki"], csr_file, cert_file, purpose,
                    ctx["ca_key_file"], ctx["ca_passfile"], ctx["ca_cert"], ctx["ca_conf"]
                )
                with open(cert_file, 'r') as cert_fp:
                    certificate = cert_fp.read()
                if not cert_file:
                    return jsonify({"error": "Failed to generate certificate"}), 500
                else:
                    chain_file = f'{cert_id}-chain.pem'
                    chain_path = os.path.join(ctx['ca_certs_dir'], chain_file)
                    convert_certificate_to_der(openssl, ctx['pki'], cert_file)
                    logging.info("DER certificate converted")
                    create_certificate_chain(cert_file, ctx['ca_chain'], chain_path)
                    convert_certificate_to_der(openssl, ctx['pki'], chain_path)
                    logging.info(chain_path)
                    
                    return jsonify({
                        'pki': ctx['pki'],
                        'ca': ctx['ca'],
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
    working_dir = chain_base_dir(pki)  # preserves your original mapping
    certs_path = issued_certs_dir_for(pki, ca)

    filename        = f"{cert_id}-cert.pem"
    chain_filename  = f"{cert_id}-chain.pem"
    full_path       = os.path.join(certs_path, filename)
    full_chain_path = os.path.join(certs_path, chain_filename)
    der_cert        = f"{full_path}.der"
    der_chain       = f"{full_chain_path}.der"
    key_filename    = os.path.join(app.config["TEMP_KEY_DIR"], f"{cert_id}.key")
    csr_file        = f"{cert_id}.csr"  # as in your original code

    _abort_if_missing(full_path, "Certificate not found")
    _abort_if_missing(der_cert, "DER certificate not found")
    _abort_if_missing(full_chain_path, "Chain certificate file NOT found")
    _abort_if_missing(der_chain, "DER chain certificate not found")
    _abort_if_missing(key_filename, "Private key not found")
    with open(key_filename, 'r') as f:
        key_content = f.read()
    try:
        stream = BytesIO()
        with ZipFile(stream, 'w') as zipf:
            zipf.write(full_path, arcname=filename) # add filename
            zipf.write(der_cert, arcname=f'{cert_id}-cert.der') # add der cert
            #zipf.write(der_chain, arcname=f'{cert_id}-chain.der') # add der chain
            zipf.writestr(f"{cert_id}.key", key_content) # add private key
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
    filename = ca_cert_path(chain, ca)
    _abort_if_missing(filename, "Certificate not found")
    try:
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({"error": "File not found"}), 404


@app.route('/<chain>/<ca>/crl', methods=['GET'])
def download_crl(chain, ca):
    ca_crl = ca_crl_path(chain, ca)
    _abort_if_missing(ca_crl, "CRL not found")
    try:
        return send_file(ca_crl, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - CRL not found: %s", ca_crl)
        return jsonify({"error": "File not found"}), 404

@app.route('/certificate_details/<chain>/<ca>/ca_certificate', methods=['GET'])
def view_ca_certificate(chain, ca):
    filename = ca_cert_path(chain, ca)
    _abort_if_missing(filename, "Certificate not found")

    try:
        if chain == "pki-44":
            openssl_cmd = f"OPENSSL_CONF={OQS_CONF} {openssl}"
            cert_data = get_ca_certificate_details(openssl_cmd, filename)
        else:
            cert_data = get_ca_certificate_details(openssl, filename)

        return render_template("view-ca-certificate.html", cert_data=cert_data, ca=ca)
    except Exception as e:
        logging.error(f"Error reading certificate: {e}")
        return jsonify({"error": "Error reading certificate"}), 500

@app.route('/crl_details/<chain>/<ca>', methods=['GET'])
def view_ca_crl(chain, ca):
    filename = ca_crl_path(chain, ca)
    _abort_if_missing(filename, "CRL not found")
    try:
        if chain == "pki-44":
            openssl_cmd = f"OPENSSL_CONF={OQS_CONF} {openssl}"
            crl_data = get_crl_details(openssl_cmd, filename)
        else:
            crl_data = get_crl_details(openssl, filename)
        return render_template("view-ca-crl.html", crl_data=crl_data, ca=ca)
    except Exception:
        return jsonify({"error": "Error reading CRL"}), 500

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(host='130.192.1.31', debug=True, port=5000)