import os
import json
import base64
import ssl
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)



