# Conor: Symmetric Message Encryption

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

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