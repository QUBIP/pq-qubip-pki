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
    OPENSSL = os.getenv("OPENSSL")
    ROOT_CA = os.getenv("ROOT_CA")
    MPU_CA = os.getenv("MPU_CA")
    MCU_CA = os.getenv("MCU_CA")

    # variables for flask HTTPS
    APP_CERT = os.getenv("APP_CERT")
    APP_CA_CERT = os.getenv("APP_CA_CERT")
    APP_ROOT_CA_CERT = os.getenv("APP_ROOT_CA_CERT")
    APP_KEY = os.getenv("APP_KEY")
    APP_CA_KEY = os.getenv("APP_CA_KEY")
    APP_ROOT_CA_KEY = os.getenv("APP_ROOT_CA_KEY")
    APP_CHAIN = os.getenv("APP_CHAIN")

    # cert purposes
    SERVER = os.getenv("SERVER")
    CLIENT = os.getenv("CLIENT")

    # ca directories and newcerts
    ROOT_CA_DIR = os.getenv("ROOT_CA_DIR")
    MPU_CA_DIR = os.getenv("MPU_CA_DIR")
    MCU_CA_DIR = os.getenv("MCU_CA_DIR")
    MPU_CERTS_DIR = os.getenv("MPU_CERTS_DIR")
    MCU_CERTS_DIR = os.getenv("MCU_CERTS_DIR")

    # ca db files
    ROOT_CA_DB = os.getenv("ROOT_CA_DB")
    MPU_CA_DB = os.getenv("MPU_CA_DB")
    MCU_CA_DB = os.getenv("MCU_CA_DB")

    # ca crl files
    ROOT_CA_CRL = os.getenv("ROOT_CA_CRL")
    MPU_CA_CRL = os.getenv("MPU_CA_CRL")
    MCU_CA_CRL = os.getenv("MCU_CA_CRL")

    # configuration files 
    MPU_CA_CONF = os.getenv("MPU_CA_CONF")
    MCU_CA_CONF = os.getenv("MCU_CA_CONF")
    SERVER_CONF = os.getenv("SERVER_CONF")
    CLIENT_CONF = os.getenv("CLIENT_CONF")

    # key and psw files
    MPU_CA_KEY = os.getenv("MPU_CA_KEY")
    MCU_CA_KEY = os.getenv("MCU_CA_KEY")
    MPU_CA_PASSWORD = os.getenv("MPU_CA_PASSWORD")
    MCU_CA_PASSWORD = os.getenv("MCU_CA_PASSWORD")

    # ca certs and chains
    ROOT_CA_CERT = os.getenv("ROOT_CA_CERT")
    MPU_CA_CERT = os.getenv("MPU_CA_CERT")
    MCU_CA_CERT = os.getenv("MCU_CA_CERT")
    MPU_CA_CHAIN= os.getenv("MPU_CA_CHAIN")
    MCU_CA_CHAIN= os.getenv("MCU_CA_CHAIN")

# Validate required variables
    @classmethod
    def validate(cls):
        required_vars = [
            "OPENSSL",
            "ROOT_CA", "MPU_CA", "MCU_CA",
            "SERVER", "CLIENT",
            "ROOT_CA_DIR", "MPU_CA_DIR", "MCU_CA_DIR",
            "MPU_CERTS_DIR", "MCU_CERTS_DIR",
            "ROOT_CA_DB", "MPU_CA_DB", "MCU_CA_DB",
            "ROOT_CA_CRL", "MPU_CA_CRL", "MCU_CA_CRL",
            "MPU_CA_CONF", "MCU_CA_CONF", "SERVER_CONF",
            "CLIENT_CONF",
            "MPU_CA_KEY", "MCU_CA_KEY",
            "MPU_CA_PASSWORD", "MCU_CA_PASSWORD",
            "ROOT_CA_CERT", "MPU_CA_CERT", "MCU_CA_CERT", "MPU_CA_CHAIN", "MCU_CA_CHAIN", "APP_CERT", "APP_CA_CERT", "APP_ROOT_CA_CERT", "APP_KEY", "APP_CA_KEY", "APP_ROOT_CA_KEY", "APP_CHAIN"

        ]
        for var in required_vars:
            if not getattr(cls, var):
                raise ValueError(f"{var} is not set in the environment variables.")