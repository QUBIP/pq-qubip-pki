from flask import Flask, request, abort, render_template, jsonify, send_file
from functools import wraps
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
AURORA_PKI = app.config["AURORA_PKI_DIR"]


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


def chain_issue_paths(ca: str):
    """Paths needed by /issue_from_csr based on ca."""
    if ca == "qubip-ca-client-fb81895b":
        return {
            "ca_certs_dir": app.config["INTERMEDIATE_CA_CLIENT_CERTS_DIR"],
            "ca_conf":      app.config["INTERMEDIATE_CA_CLIENT_CONF"],
            "ca_key_file":  app.config["INTERMEDIATE_CA_CLIENT_KEY"],
            "ca_passfile":  app.config["INTERMEDIATE_CA_CLIENT_PASSWORD"],
            "ca_cert":      app.config["INTERMEDIATE_CA_CLIENT_CERT"],
            "ca_chain":     app.config["INTERMEDIATE_CA_CLIENT_CHAIN"],
            "extensions":   "client_ext"
        }
    if ca == "qubip-ca-server-fb81895b":
        return {
            "ca_certs_dir": app.config["INTERMEDIATE_CA_SERVER_CERTS_DIR"],
            "ca_conf":      app.config["INTERMEDIATE_CA_SERVER_CONF"],
            "ca_key_file":  app.config["INTERMEDIATE_CA_SERVER_KEY"],
            "ca_passfile":  app.config["INTERMEDIATE_CA_SERVER_PASSWORD"],
            "ca_cert":      app.config["INTERMEDIATE_CA_SERVER_CERT"],
            "ca_chain":     app.config["INTERMEDIATE_CA_SERVER_CHAIN"],
            "extensions":   "server_ext"
        }
    if ca == "qubip-ca-server-mcu-fb81895b":
        return {
            "ca_certs_dir": app.config["INTERMEDIATE_CA_SERVER_MCU_CERTS_DIR"],
            "ca_conf":      app.config["INTERMEDIATE_CA_SERVER_MCU_CONF"],
            "ca_key_file":  app.config["INTERMEDIATE_CA_SERVER_MCU_KEY"],
            "ca_passfile":  app.config["INTERMEDIATE_CA_SERVER_MCU_PASSWORD"],
            "ca_cert":      app.config["INTERMEDIATE_CA_SERVER_MCU_CERT"],
            "ca_chain":     app.config["INTERMEDIATE_CA_SERVER_MCU_CHAIN"],
            "extensions":   "server_ext"
        }
    if ca == "qubip-ca-client-mcu-fb81895b":
        return {
            "ca_certs_dir": app.config["INTERMEDIATE_CA_CLIENT_MCU_CERTS_DIR"],
            "ca_conf":      app.config["INTERMEDIATE_CA_CLIENT_MCU_CONF"],
            "ca_key_file":  app.config["INTERMEDIATE_CA_CLIENT_MCU_KEY"],
            "ca_passfile":  app.config["INTERMEDIATE_CA_CLIENT_MCU_PASSWORD"],
            "ca_cert":      app.config["INTERMEDIATE_CA_CLIENT_MCU_CERT"],
            "ca_chain":     app.config["INTERMEDIATE_CA_CLIENT_MCU_CHAIN"],
            "extensions":   "client_ext"
        }
    abort(400, "Invalid chain")

def cert_ctx(purpose: str, chain: str = "default") -> dict:
    """
    Paths & config needed by /generate_certificate based on device + purpose.
    (Same logic; just centralized.)
    """
    if chain == "default":
        if purpose == "client":
            conf_file = app.config["CLIENT_CONF"]
            return {
                "ca": app.config["INTERMEDIATE_CA_CLIENT"],
                "ca_certs_dir": app.config["INTERMEDIATE_CA_CLIENT_CERTS_DIR"],
                "ca_conf":      app.config["INTERMEDIATE_CA_CLIENT_CONF"],
                "ca_key_file":  app.config["INTERMEDIATE_CA_CLIENT_KEY"],
                "ca_passfile":  app.config["INTERMEDIATE_CA_CLIENT_PASSWORD"],
                "ca_cert":       app.config["INTERMEDIATE_CA_CLIENT_CERT"],
                "ca_chain":      app.config["INTERMEDIATE_CA_CLIENT_CHAIN"],
                "conf_file":    conf_file,
                "extensions":   "client_ext"
            }
        if purpose == "server":
            conf_file = app.config["SERVER_CONF"]
            return {
                "ca": app.config["INTERMEDIATE_CA_SERVER"],
                "ca_certs_dir": app.config["INTERMEDIATE_CA_SERVER_CERTS_DIR"],
                "ca_conf":      app.config["INTERMEDIATE_CA_SERVER_CONF"],
                "ca_key_file":  app.config["INTERMEDIATE_CA_SERVER_KEY"],
                "ca_passfile":  app.config["INTERMEDIATE_CA_SERVER_PASSWORD"],
                "ca_cert":       app.config["INTERMEDIATE_CA_SERVER_CERT"],
                "ca_chain":      app.config["INTERMEDIATE_CA_SERVER_CHAIN"],
                "conf_file":    conf_file,
                "extensions":   "server_ext"
            }
    else:
        # chain == mcu
        if purpose == "client":
            conf_file = app.config["CLIENT_CONF"]
            return {
                "ca": app.config["INTERMEDIATE_CA_CLIENT_MCU"],
                "ca_certs_dir": app.config["INTERMEDIATE_CA_CLIENT_MCU_CERTS_DIR"],
                "ca_conf":      app.config["INTERMEDIATE_CA_CLIENT_MCU_CONF"],
                "ca_key_file":  app.config["INTERMEDIATE_CA_CLIENT_MCU_KEY"],
                "ca_passfile":  app.config["INTERMEDIATE_CA_CLIENT_MCU_PASSWORD"],
                "ca_cert":       app.config["INTERMEDIATE_CA_CLIENT_MCU_CERT"],
                "ca_chain":      app.config["INTERMEDIATE_CA_CLIENT_MCU_CHAIN"],
                "conf_file":    conf_file,
                "extensions":   "client_ext"
            }
        if purpose == "server":
            conf_file = app.config["SERVER_CONF"]
            return {
                "ca": app.config["INTERMEDIATE_CA_SERVER_MCU"],
                "ca_certs_dir": app.config["INTERMEDIATE_CA_SERVER_MCU_CERTS_DIR"],
                "ca_conf":      app.config["INTERMEDIATE_CA_SERVER_MCU_CONF"],
                "ca_key_file":  app.config["INTERMEDIATE_CA_SERVER_MCU_KEY"],
                "ca_passfile":  app.config["INTERMEDIATE_CA_SERVER_MCU_PASSWORD"],
                "ca_cert":       app.config["INTERMEDIATE_CA_SERVER_MCU_CERT"],
                "ca_chain":      app.config["INTERMEDIATE_CA_SERVER_MCU_CHAIN"],
                "conf_file":    conf_file,
                "extensions":   "server_ext"
            }
    abort(400, f"Invalid purpose: {purpose}")

def chain_base_dir() -> str:
    return AURORA_PKI + "/certs"

def ca_cert_path(ca: str) -> str:
    base = chain_base_dir()
    if ca == "qubip-root-ca-fb81895b":
        return app.config['ROOT_CA_CERT']
    if ca == "qubip-ca-client-fb81895b":
        return app.config['INTERMEDIATE_CA_CLIENT_CERT']
    if ca == "qubip-ca-server-fb81895b":
        return app.config['INTERMEDIATE_CA_SERVER_CERT']
    if ca == "qubip-ca-client-mcu-fb81895b":
        return app.config['INTERMEDIATE_CA_CLIENT_MCU_CERT']
    if ca == "qubip-ca-server-mcu-fb81895b":
        return app.config['INTERMEDIATE_CA_SERVER_MCU_CERT']
    abort(404, "CA not found")

def ca_crl_path(ca: str) -> str:
    base = chain_base_dir()
    if ca == "qubip-root-ca-fb81895b":
        return app.config['ROOT_CA_CRL_DER']
    if ca == "qubip-ca-client-fb81895b":
        return app.config['INTERMEDIATE_CA_CLIENT_CRL_DER']
    if ca == "qubip-ca-server-fb81895b":
        return app.config['INTERMEDIATE_CA_SERVER_CRL_DER']
    if ca == "qubip-ca-client-mcu-fb81895b":
        return app.config['INTERMEDIATE_CA_CLIENT_MCU_CRL_DER']
    if ca == "qubip-ca-server-mcu-fb81895b":
        return app.config['INTERMEDIATE_CA_SERVER_MCU_CRL_DER']
    abort(404, "CA not found")

def issued_certs_dir_for(ca: str) -> str:
    base = chain_base_dir()
    if ca == "qubip-ca-client-fb81895b":
        return app.config['INTERMEDIATE_CA_CLIENT_CERTS_DIR']
    if ca == "qubip-ca-server-fb81895b":
        return app.config['INTERMEDIATE_CA_SERVER_CERTS_DIR']
    if ca == "qubip-ca-client-mcu-fb81895b":
        return app.config['INTERMEDIATE_CA_CLIENT_MCU_CERTS_DIR']
    if ca == "qubip-ca-server-mcu-fb81895b":
        return app.config['INTERMEDIATE_CA_SERVER_MCU_CERTS_DIR']
    abort(404, "CA not found")

def load_cert_from_store(ca: str, certificate_id: str) -> str:
    """Load certificate PEM from storage based on pki, ca, and certificate_id."""
    certs_dir = issued_certs_dir_for(ca)
    cert_path = os.path.join(certs_dir, f"{certificate_id}-cert.pem")
    if not os.path.exists(cert_path):
        return None
    with open(cert_path, 'r') as f:
        return f.read()
# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.post('/v2/certs/issue_from_csr')
def issue_from_csr():
    # read form fields
    chain = request.form.get("chain", "default").strip().lower()
    purpose = request.form.get("purpose", "").strip()
    ca = ""
    if purpose not in {"server", "client"}:
        abort(400, "Invalid purpose")
    if purpose == "client":
        if chain == "default":
            ca = "qubip-ca-client-fb81895b"
        else:            
            ca = "qubip-ca-client-mcu-fb81895b"
    
    elif purpose == "server":
        if chain == "default":
            ca = "qubip-ca-server-fb81895b"
        else:
            ca = "qubip-ca-server-mcu-fb81895b"
    paths = chain_issue_paths(ca)
    out_format = request.form.get("out_format", "pem").strip().lower()
    if out_format not in {"pem", "der"}:
        abort(400, "Invalid output format")
    include_chain = "include_chain" in request.form # checkbox

    up = request.files.get("csr")
    if not up or up.filename == "":
        abort(400, "CSR file is required")
    # 3) Work in an isolated temp dir
    workdir = tempfile.mkdtemp(prefix="csr_issue_")
    try:
        csr_path = os.path.join("/tmp/", "input.csr")
        up.save(csr_path)
        

        # 4) Issue certificate (always produce PEM first)
        leaf_id = f'{str(uuid.uuid4().hex[:10 ])}-{purpose}'
        leaf_pem = os.path.join(workdir, f"{leaf_id}-cert.pem")
        sign_certificate(
            openssl, csr_path, leaf_pem,
            paths["ca_key_file"], paths["ca_passfile"], paths["ca_cert"], paths["ca_conf"], paths['extensions']
        )
        # 5) Optionally build bundle
        download_path = leaf_pem
        download_name = f"{leaf_id}-cert.pem"
        if include_chain:
            bundle_pem = os.path.join(workdir, "bundle.pem")
            der_file = create_certificate_chain(leaf_pem, paths['ca_chain'], bundle_pem)
            download_path = bundle_pem
            download_name = f"{leaf_id}-chain.pem"

        # 6) Convert to DER if requested
        if out_format == "der":
            # der_path = os.path.join(workdir, "leaf.der")
            # If bundle was requested with DER, you likely still return leaf.der (bundling DER is uncommon).
            der_path = convert_certificate_to_der(openssl, leaf_pem)
            print(der_path)
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


@app.route('/v2/generate_certificate/<purpose>', methods=['GET','POST'])

def generate_certificate(purpose):
    if request.method == 'GET':
        return render_template('gen-cert.html', purpose=purpose)
    if request.method == 'POST':
        try:
            data = request.json or request.form
            logging.info(f"Received certificate generation request: {data}")
            chain = data.get('chain', 'default')  # default to "default" if not provided
            ctx = cert_ctx(purpose, chain)
            algorithm = data.get('algorithm') 
            commonName = data.get('common_name')
            cn_type = data.get('cn_type') # IP/DNS
            cert_id = f'{str(uuid.uuid4().hex[:10 ])}-{purpose}' 

            if not os.path.exists(app.config['TEMP_KEY_DIR']):
                os.makedirs(app.config['TEMP_KEY_DIR'])
            key_file = os.path.join(app.config['TEMP_KEY_DIR'], f'{cert_id}.key')
            generate_private_key(openssl, key_file, algorithm)
            if not key_file:
                return render_template('error.html', message="Failed to generate private key"), 500
            else:
                subjectAltName = commonName
                subj = f"/C=EU/O=QUBIP/CN={commonName}"
                csr_file = os.path.join(ctx['ca_certs_dir'], f'{cert_id}.csr')
                generate_csr(
                    openssl, key_file, csr_file, subj, ctx["conf_file"],
                    commonName, subjectAltName, cn_type
                )          
                if not csr_file:
                    return render_template('error.html', message="Failed to generate CSR"), 500
                cert_file = os.path.join(ctx['ca_certs_dir'], f'{cert_id}-cert.pem')
                sign_certificate(
                    openssl, csr_file, cert_file,
                    ctx["ca_key_file"], ctx["ca_passfile"], ctx["ca_cert"], ctx["ca_conf"], ctx['extensions']
                )
                with open(cert_file, 'r') as cert_fp:
                    certificate = cert_fp.read()
                if not cert_file:
                    return jsonify({"error": "Failed to generate certificate"}), 500
                else:
                    chain_file = f'{cert_id}-chain.pem'
                    chain_path = os.path.join(ctx['ca_certs_dir'], chain_file)
                    der_file = convert_certificate_to_der(openssl, cert_file)
                    der_ca_file = create_certificate_chain(cert_file, ctx['ca_chain'], chain_path)
                    convert_certificate_to_der(openssl, chain_path)
                    
                    return jsonify({
                        'ca': ctx['ca'],
                        'certificate_id': cert_id,
                        'certificate': certificate,
                        'filename': f'{cert_id}.pem'
                        }), 200
        except Exception as e:
            logging.error(f"Error generating certificate: {e}")
            return jsonify({'error': 'An unexpected error occurred', 'details': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 400

@app.route('/v2/download_certificate/<cert_id>', methods=['GET'])

def download_certificate(cert_id):
    purpose = cert_id.split("-")[1]
    ca = ""
    if purpose == "client":
        ca = "qubip-ca-client-fb81895b"
    else:
        ca = "qubip-ca-server-fb81895b"
    certs_path = issued_certs_dir_for(ca)
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

@app.route('/v2/certs/<ca>/certificate', methods=['GET'])

def download_ca_certificate(ca):
    filename = ca_cert_path(ca)
    _abort_if_missing(filename, "Certificate not found")
    try:
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - Certificate not found: %s", filename)
        return jsonify({"error": "File not found"}), 404


@app.route('/v2/certs/<ca>/crl', methods=['GET'])

def download_crl(ca):
    ca_crl = ca_crl_path(ca)
    _abort_if_missing(ca_crl, "CRL not found")
    try:
        return send_file(ca_crl, as_attachment=True)
    except FileNotFoundError:
        logging.error("app.py - CRL not found: %s", ca_crl)
        return jsonify({"error": "File not found"}), 404

@app.route('/v2/certificate_details/<ca>/ca_certificate', methods=['GET'])

def view_ca_certificate(ca):
    filename = ca_cert_path(ca)
    _abort_if_missing(filename, "Certificate not found")

    try:
        cert_data = get_ca_certificate_details(openssl, filename)
        return render_template("view-ca-certificate.html", cert_data=cert_data, ca=ca)
    except Exception as e:
        logging.error(f"Error reading certificate: {e}")
        return render_template("error.html", message="Error reading certificate"), 500

@app.route('/v2/crl_details/<ca>', methods=['GET'])

def view_ca_crl(ca):
    filename = ca_crl_path(ca)
    _abort_if_missing(filename, "CRL not found")
    try:
        crl_data = get_crl_details(openssl, filename)
        return render_template("view-ca-crl.html", crl_data=crl_data, ca=ca)
    except Exception as e:
        logging.error(f"Error reading CRL: {e}")
        return render_template("error.html", message="Error reading CRL"), 500
    
@app.route('/v2/certificate/<ca>/<certificate_id>')

def certificate_success(ca, certificate_id):
    cert_pem = load_cert_from_store(ca, certificate_id)  # <-- implement this

    if not cert_pem:
        return render_template('error.html', message="Certificate not found"), 404

    return render_template('certificate_success.html',
                           ca=ca, certificate_id=certificate_id,
                           cert_pem=cert_pem)

@app.route('/issue', methods=['GET'])
def issue_dashboard():
    return render_template('issue_dashboard.html')


@app.route('/')

def home():
    return render_template('home.html')

if __name__ == '__main__':
    logging.info("Starting QUBIP PKI Flask app")
    logging.info(Config.__dict__)
    app.run(host='130.192.1.31', debug=True, port=5000)