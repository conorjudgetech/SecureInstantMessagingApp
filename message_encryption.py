# Conor: Symmetric Message Encryption with Per-Message Key Derivation

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def derive_per_message_key(shared_secret, salt, info):
    """
    Derive a per-message key using HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)

def encrypt_message(plaintext, key):
    """
    Encrypt the plaintext using AES-256-GCM.
    Returns the ciphertext and nonce.
    """
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce

def decrypt_message(ciphertext, nonce, key):
    """
    Decrypt the ciphertext using AES-256-GCM.
    Returns the plaintext.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
