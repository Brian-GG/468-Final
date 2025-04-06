import os
import json
import base64
import ssl
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519
from datetime import datetime, timedelta
import socket
import ipaddress

CERT_DIR = "file_vault"

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

def decrypt_file(encrypted_file_path, password, file_return):
    with open(encrypted_file_path, "r") as f:
        encrypted_data = json.load(f)

    encrypted_data = base64.b64decode(encrypted_data["data"])
    key = derive_key(password)
    f = Fernet(key)
    plaintext = f.decrypt(encrypted_data)

    if file_return == 0:
        return plaintext
    decrypted_file_path = encrypted_file_path.replace(".enc", "")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)
    return decrypted_file_path

def hash_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()

def sign_file_hash(hash, password):
    with open("file_vault/client.key.enc", "rb") as f:
        encrypted_data = json.load(f)
    
    encrypted_data = base64.b64decode(encrypted_data["data"])
    key = derive_key(password)
    f = Fernet(key)
    plaintext = f.decrypt(encrypted_data)
    private_key = serialization.load_pem_private_key(plaintext, password=None)
    print(type(private_key))
    signature = private_key.sign(
        hash.encode()
    )

    return signature

def save_key(key, filename):
    with open(os.path.join(CERT_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def save_cert(cert, filename):
    with open(os.path.join(CERT_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def create_root_ca():
    # Use a fixed seed for deterministic key generation
    seed = b"fixed_seed_for_root_ca"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"fixed_salt_for_root_ca",
        iterations=100000,
    )
    derived_key = kdf.derive(seed)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(derived_key)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])

    serial_number = 123456789
    not_valid_before = datetime(2025, 1, 1)
    not_valid_after = datetime(2035, 1, 1)

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(serial_number) \
        .not_valid_before(not_valid_before) \
        .not_valid_after(not_valid_after) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(private_key=private_key, algorithm=None)

    save_key(private_key, "ca.key")
    save_cert(cert, "ca.crt")
    print("Root CA created.")

    return private_key, cert

def create_server_cert(ip, ca_key, ca_cert):
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)])

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(ca_cert.subject) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(ip),
            x509.IPAddress(ipaddress.IPv4Address(local_ip))  # Add the local IP address as an alternative name
        ]), critical=False) \
        .sign(private_key=ca_key, algorithm=None)

    save_key(key, "server.key")
    save_cert(cert, "server.crt")
    print("Server certificate created.")

def create_client_cert(ca_key, ca_cert):
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "P2PAgentClient")])

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(ca_cert.subject) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.utcnow()) \
        .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True) \
        .sign(private_key=ca_key, algorithm=None)

    save_key(key, "client.key")
    save_cert(cert, "client.crt")
    print("Client certificate created.")