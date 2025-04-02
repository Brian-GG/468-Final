import os
import json
import base64
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def derive_key(password):
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'~8F\x81\x19\xbf\xc8\\\xa2V;S\xc5s\xdfT',
    iterations=1_200_000,
    )
    seed = password.encode()
    key = base64.urlsafe_b64encode(kdf.derive(seed))
    return key

def encrypt_file(file_path, password):
    key = derive_key(password)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    f = Fernet(key)
    encrypted_data = f.encrypt(plaintext)
    encoded_encrypted = base64.b64encode(encrypted_data).decode('utf-8')

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "w") as f:
        json.dump({"data": encoded_encrypted}, f, indent=4)

    os.remove(file_path)

def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, "r") as f:
        encrypted_data = json.load(f)

    encrypted_data = base64.b64decode(encrypted_data["data"])
    key = derive_key(password)
    f = Fernet(key)
    plaintext = f.decrypt(encrypted_data)

    decrypted_file_path = encrypted_file_path.replace(".enc", "")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)
    return decrypted_file_path

def hash_file(file_path):
    hasher = hashes.Hash(hashes.SHA256())
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return base64.urlsafe_b64encode(hasher.finalize()).decode('utf-8')

def sign_file_hash(hash, password):
    with open("file_vault/key.pem.enc", "rb") as f:
        encrypted_data = json.load(f)
    
    encrypted_data = base64.b64decode(encrypted_data["data"])
    key = derive_key(password)
    f = Fernet(key)
    plaintext = f.decrypt(encrypted_data)
    private_key = serialization.load_pem_private_key(plaintext, password=b"passphrase")

    signature = private_key.sign(
        hash.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature
