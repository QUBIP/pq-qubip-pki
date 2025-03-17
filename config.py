from dotenv import load_dotenv
import os

# Determine the environment
env = os.getenv("FLASK_ENV", "development")

# Load the appropriate .env file
if env == "production":
    load_dotenv(".env.prod")
else:
    load_dotenv(".env.dev")

class Config:

    # Application-specific configurations
    ROOT_CA = os.getenv("ROOT_CA")
    TLS_CA = os.getenv("TLS_CA")
    SOFTWARE_CA = os.getenv("SOFTWARE_CA")

    # cert purposes
    TLS_SERVER = os.getenv("TLS_SERVER")
    TLS_CLIENT = os.getenv("TLS_CLIENT")
    CODESIGN = os.getenv("CODESIGN")

    # ca directories and newcerts
    ROOT_CA_DIR = os.getenv("ROOT_CA_DIR")
    TLS_CA_DIR = os.getenv("TLS_CA_DIR")
    SOFTWARE_CA_DIR = os.getenv("SOFTWARE_CA_DIR")
    TLS_CERTS_DIR = os.getenv("TLS_CERTS_DIR")
    SOFTWARE_CERTS_DIR = os.getenv("SOFTWARE_CERTS_DIR")

    # ca db files
    ROOT_CA_DB = os.getenv("ROOT_CA_DB")
    TLS_CA_DB = os.getenv("TLS_CA_DB")
    SOFTWARE_CA_DB = os.getenv("SOFTWARE_CA_DB")

    # ca crl files
    ROOT_CA_CRL = os.getenv("ROOT_CA_CRL")
    TLS_CA_CRL = os.getenv("TLS_CA_CRL")
    SOFTWARE_CA_CRL = os.getenv("SOFTWARE_CA_CRL")

    # configuration files 
    TLS_CA_CONF = os.getenv("TLS_CA_CONF")
    SOFTWARE_CA_CONF = os.getenv("SOFTWARE_CA_CONF")
    TLS_SERVER_CONF = os.getenv("TLS_SERVER_CONF")
    TLS_CLIENT_CONF = os.getenv("TLS_CLIENT_CONF")
    CODESIGN_CONF = os.getenv("CODESIGN_CONF")

    # key and psw files
    TLS_CA_KEY = os.getenv("TLS_CA_KEY")
    SOFTWARE_CA_KEY = os.getenv("SOFTWARE_CA_KEY")
    TLS_CA_PASSWORD = os.getenv("TLS_CA_PASSWORD")
    SOFTWARE_CA_PASSWORD = os.getenv("SOFTWARE_CA_PASSWORD")

    # ca certs and chains
    ROOT_CA_CERT = os.getenv("ROOT_CA_CERT")
    TLS_CA_CERT = os.getenv("TLS_CA_CERT")
    SOFTWARE_CA_CERT = os.getenv("SOFTWARE_CA_CERT")

# Validate required variables
    @classmethod
    def validate(cls):
        required_vars = [
            "ROOT_CA", "TLS_CA", "SOFTWARE_CA",
            "TLS_SERVER", "TLS_CLIENT", "CODESIGN",
            "ROOT_CA_DIR", "TLS_CA_DIR", "SOFTWARE_CA_DIR",
            "TLS_CERTS_DIR", "SOFTWARE_CERTS_DIR",
            "ROOT_CA_DB", "TLS_CA_DB", "SOFTWARE_CA_DB",
            "ROOT_CA_CRL", "TLS_CA_CRL", "SOFTWARE_CA_CRL",
            "TLS_CA_CONF", "SOFTWARE_CA_CONF", "TLS_SERVER_CONF",
            "TLS_CLIENT_CONF", "CODESIGN_CONF",
            "TLS_CA_KEY", "SOFTWARE_CA_KEY",
            "TLS_CA_PASSWORD", "SOFTWARE_CA_PASSWORD",
            "ROOT_CA_CERT", "TLS_CA_CERT", "SOFTWARE_CA_CERT"
        ]
        for var in required_vars:
            if not getattr(cls, var):
                raise ValueError(f"{var} is not set in the environment variables.")