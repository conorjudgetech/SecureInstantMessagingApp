# digital_signature.py
# Siddarth: Digital Signatures with Certificates and Audit Logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute, BasicConstraints
)
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography import x509
import datetime
import json
import logging

# Configure logging for digital_signature.py
logging.basicConfig(
    filename='signature_verification.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

def generate_signature_key_pair(username):
    """
    Generate Ed25519 signature key pair and a self-signed certificate.
    Returns the private key and certificate.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Create a self-signed certificate
    subject = issuer = Name([
        NameAttribute(NameOID.COMMON_NAME, username),
    ])
    cert_builder = CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(issuer)
    cert_builder = cert_builder.public_key(public_key)
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    cert_builder = cert_builder.add_extension(
        BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = cert_builder.sign(private_key, algorithm=None)

    return private_key, certificate

def sign_message(private_key, ciphertext):
    """
    Sign the ciphertext with the private key and include a timestamp.
    Returns the signature and timestamp.
    """
    timestamp = datetime.datetime.utcnow().isoformat().encode('utf-8')
    data_to_sign = ciphertext + timestamp  # Ensure consistency with verification
    signature = private_key.sign(data_to_sign)
    return signature, timestamp

def verify_signature(public_key_pem, ciphertext, signature, timestamp):
    """
    Verify the message signature with the public key and log the attempt.
    Returns True if verification succeeds, False otherwise.
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_pem.encode('utf-8'))
        data_to_verify = ciphertext + timestamp  # Must match sign_message
        public_key.verify(signature, data_to_verify)
        
        # Log successful verification
        log_entry = {
            "public_key": public_key_pem,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "success": True
        }
        logging.info(json.dumps(log_entry))
        return True
    except Exception as e:
        # Log failed verification with error message
        log_entry = {
            "public_key": public_key_pem,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "success": False,
            "error": str(e)
        }
        logging.error(json.dumps(log_entry))
        return False