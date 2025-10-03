"""
Cryptography service module for secure file and message sharing.
Provides RSA key generation, hybrid encryption, and decryption functionality.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import struct


def generate_rsa_keypair(key_size=2048):
    """
    Generate RSA key pair and return as PEM-encoded bytes.
    
    Args:
        key_size (int): Size of RSA key in bits (default: 2048)
    
    Returns:
        tuple: (private_key_pem, public_key_pem) as bytes
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    
    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key and serialize to PEM format
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return (private_key_pem, public_key_pem)


def hybrid_encrypt(data, public_key_pem, content_type="text"):
    """
    Encrypt data using hybrid encryption (RSA + AES-GCM).
    
    Args:
        data (bytes): Data to encrypt
        public_key_pem (bytes): Recipient's public key in PEM format
        content_type (str): Type of content (e.g., "text", "image/png")
    
    Returns:
        bytes: Encrypted package containing all necessary components
    """
    # Generate random 256-bit AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    
    # Create AESGCM cipher
    aesgcm = AESGCM(aes_key)
    
    # Generate random nonce (12 bytes is recommended for GCM)
    nonce = os.urandom(12)
    
    # Encrypt data with AES-GCM (this also generates the authentication tag)
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    
    # Load recipient's public key
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    # Encrypt AES key with RSA public key using OAEP padding
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Package everything into binary format
    # Format: [len(encrypted_aes_key)][encrypted_aes_key][len(nonce)][nonce]
    #         [len(tag)][tag][len(content_type)][content_type][encrypted_data]
    # Note: AES-GCM combines ciphertext and tag, so we need to extract the tag
    # The last 16 bytes of encrypted_data is the tag
    ciphertext = encrypted_data[:-16]
    tag = encrypted_data[-16:]
    
    content_type_bytes = content_type.encode('utf-8')
    
    package = b''
    package += struct.pack('!I', len(encrypted_aes_key))
    package += encrypted_aes_key
    package += struct.pack('!I', len(nonce))
    package += nonce
    package += struct.pack('!I', len(tag))
    package += tag
    package += struct.pack('!I', len(content_type_bytes))
    package += content_type_bytes
    package += ciphertext
    
    return package


def hybrid_decrypt(encrypted_package, private_key_pem):
    """
    Decrypt data using hybrid decryption (RSA + AES-GCM).
    
    Args:
        encrypted_package (bytes): Encrypted package from hybrid_encrypt
        private_key_pem (bytes): Private key in PEM format
    
    Returns:
        tuple: (decrypted_data, content_type)
    """
    # Parse the encrypted package
    offset = 0
    
    # Extract encrypted AES key
    encrypted_aes_key_len = struct.unpack('!I', encrypted_package[offset:offset+4])[0]
    offset += 4
    encrypted_aes_key = encrypted_package[offset:offset+encrypted_aes_key_len]
    offset += encrypted_aes_key_len
    
    # Extract nonce
    nonce_len = struct.unpack('!I', encrypted_package[offset:offset+4])[0]
    offset += 4
    nonce = encrypted_package[offset:offset+nonce_len]
    offset += nonce_len
    
    # Extract tag
    tag_len = struct.unpack('!I', encrypted_package[offset:offset+4])[0]
    offset += 4
    tag = encrypted_package[offset:offset+tag_len]
    offset += tag_len
    
    # Extract content type
    content_type_len = struct.unpack('!I', encrypted_package[offset:offset+4])[0]
    offset += 4
    content_type = encrypted_package[offset:offset+content_type_len].decode('utf-8')
    offset += content_type_len
    
    # Extract encrypted data (ciphertext)
    ciphertext = encrypted_package[offset:]
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    
    # Decrypt AES key using RSA private key with OAEP padding
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create AESGCM cipher with decrypted key
    aesgcm = AESGCM(aes_key)
    
    # Decrypt data using AES-GCM (need to combine ciphertext and tag)
    encrypted_data_with_tag = ciphertext + tag
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data_with_tag, None)
    
    return (decrypted_data, content_type)
