# 4: Digital Signatures

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_public_key, load_pem_private_key
)

def generate_signature_key_pair():
    """
    Generate Ed25519 signature key pair.
    Returns the private key and public key.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    """
    Sign the message with the private key.
    Returns the signature.
    """
    signature = private_key.sign(message)
    return signature

def verify_signature(public_key, message, signature):
    """
    Verify the message signature with the public key.
    Returns True if verification succeeds, False otherwise.
    """
    try:
        public_key.verify(signature, message)
        return True
    except:
        return False