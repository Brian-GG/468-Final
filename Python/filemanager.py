import os
import json
import shutil
import datetime
from login import *
from encryption import *
from pathlib import Path

def create_user_file():
    user_file = "user.json"
    if not os.path.exists(user_file):
        with open(user_file, "w") as f:
            json.dump({}, f)
        newPassword = input("New Client! Create a Password:\n")
        password = register_user(newPassword)
        files_folder= "file_vault"
        
        if not os.path.exists("file_vault"):
            files_folder = Path("file_vault")
            files_folder.mkdir(parents=True, exist_ok=True)
        
        generate_self_cert(password)

        return password

def create_data_files():
    peers_file = "peers.json"
    if not os.path.exists(peers_file):
        with open(peers_file, "w") as f:
            json.dump({}, f)

    files_db = "filedb.json"
    if not os.path.exists(files_db):
        with open(files_db, "w") as f:
            json.dump({}, f)

def import_files(password):
    input_file = input("Enter original file path: \n")
    dest_folder = Path("file_vault")
    original_path = Path(input_file)

    if not original_path.exists():
        print("Error: File Not Found!")
        return
    
    dest_path = dest_folder / original_path.name
    shutil.copy2(str(original_path), str(dest_path))

    encrypt_file(str(dest_path), password)
    print("File Uploaded!\n")

def generate_self_cert(password):
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )

    with open("file_vault/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ontario"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Richmond Hill"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grigore Inc"),
    x509.NameAttribute(NameOID.COMMON_NAME, "secureshare.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    with open("file_vault/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    encrypt_file("file_vault/key.pem", password)
    
    


    


