"""
crypto_utils.py - Cryptographic Primitives for CryptoSign
Uses the `cryptography` library for all operations.
"""

import hashlib
import base64
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


# ─────────────────────────────────────────────
# RSA Key Generation
# ─────────────────────────────────────────────
def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ─────────────────────────────────────────────
# Serialization
# ─────────────────────────────────────────────
def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key_encrypted(private_key: RSAPrivateKey, password: str) -> bytes:
    """Serialize and encrypt a private key with a password (PKCS8 / BestAvailableEncryption)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )


def load_private_key(pem_data: bytes, password: str) -> RSAPrivateKey:
    """Load an encrypted private key from PEM bytes."""
    return serialization.load_pem_private_key(
        pem_data,
        password=password.encode('utf-8'),
        backend=default_backend()
    )


# ─────────────────────────────────────────────
# Key Fingerprint
# ─────────────────────────────────────────────
def get_key_fingerprint(public_key: RSAPublicKey) -> str:
    """Return SHA-256 fingerprint of the public key (hex)."""
    pub_bytes = serialize_public_key(public_key)
    digest = hashlib.sha256(pub_bytes).hexdigest()
    # Format as pairs: AA:BB:CC...
    return ':'.join(digest[i:i+2].upper() for i in range(0, min(40, len(digest)), 2))


# ─────────────────────────────────────────────
# Digital Signatures (RSA-PSS with SHA-256)
# ─────────────────────────────────────────────
def sign_file_data(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256.
    RSA-PSS provides stronger security guarantees than PKCS#1 v1.5.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_file_signature(public_key: RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify an RSA-PSS signature. Returns True if valid, False otherwise.
    Prevents MITM and replay attacks by binding data to signature.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
# Self-Signed X.509 Certificate Generation
# ─────────────────────────────────────────────
def generate_certificate(private_key: RSAPrivateKey,
                          public_key: RSAPublicKey,
                          common_name: str,
                          valid_days: int = 365) -> bytes:
    """
    Generate a self-signed X.509 certificate for the key pair.
    Used for certificate-based authentication.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            "Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "CryptoSign"),
        x509.NameAttribute(NameOID.COMMON_NAME,              common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return cert.public_bytes(serialization.Encoding.PEM)


# ─────────────────────────────────────────────
# Hybrid Encryption (RSA + AES-GCM)
# ─────────────────────────────────────────────
def encrypt_message(public_key: RSAPublicKey, message: bytes) -> dict:
    """
    Hybrid encryption:
      1. Generate a random AES-256 session key
      2. Encrypt message with AES-GCM
      3. Encrypt session key with RSA-OAEP
    Returns dict with encrypted_key and ciphertext (both base64-encoded).
    """
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = os.urandom(32)   # AES-256
    nonce       = os.urandom(12)   # 96-bit nonce for GCM
    aesgcm      = AESGCM(session_key)
    ciphertext  = aesgcm.encrypt(nonce, message, None)

    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'nonce':         base64.b64encode(nonce).decode(),
        'ciphertext':    base64.b64encode(ciphertext).decode(),
    }


def decrypt_message(private_key: RSAPrivateKey, encrypted_data: dict) -> bytes:
    """
    Decrypt a hybrid-encrypted message.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
    nonce         = base64.b64decode(encrypted_data['nonce'])
    ciphertext    = base64.b64decode(encrypted_data['ciphertext'])

    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm    = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
