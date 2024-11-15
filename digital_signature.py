# Sid: Digital Signatures with Certificates and Audit Logging

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
    certificate = cert_builder.sign(private_key, hashes.SHA256())

    return private_key, certificate

def sign_message(private_key, message):
    """
    Sign the message with the private key and include a timestamp.
    Returns the signature and timestamp.
    """
    timestamp = datetime.datetime.utcnow().isoformat().encode()
    data_to_sign = timestamp + b'||' + message
    signature = private_key.sign(data_to_sign)
    return signature, timestamp

def verify_signature(public_key, message, signature, timestamp):
    """
    Verify the message signature with the public key and log the attempt.
    Returns True if verification succeeds, False otherwise.
    """
    data_to_verify = timestamp + b'||' + message
    try:
        public_key.verify(signature, data_to_verify)
        log_signature_verification(public_key, True)
        return True
    except Exception:
        log_signature_verification(public_key, False)
        return False

def log_signature_verification(public_key, success):
    """
    Log signature verification attempts for auditing.
    """
    log_entry = {
        'public_key': public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'success': success
    }
    with open('signature_verification.log', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
