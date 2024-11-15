# 3: Secure Key Exchange with Ephemeral Keys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_public_key, load_pem_private_key
)

def generate_ecdh_key_pair():
    """
    Generate a static ECDH key pair using SECP256R1 curve.
    Returns the private key and public key.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ephemeral_key_pair():
    """
    Generate an ephemeral ECDH key pair using SECP256R1 curve.
    Returns the private key and public key.
    """
    return generate_ecdh_key_pair()

def derive_shared_key(private_key, peer_public_key):
    """
    Derive shared key using ECDH.
    Returns the shared key (first 32 bytes for AES-256).
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key[:32]  # Use the first 32 bytes for AES-256
