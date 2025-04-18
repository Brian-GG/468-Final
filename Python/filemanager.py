import os
import json
import re
import shutil
import datetime
import hashlib
from login import *
from encryption import *
from pathlib import Path
from os import listdir
from os.path import isfile, join

def create_user_file():
    user_file = "user.json"
    if not os.path.exists(user_file):
        with open(user_file, "w") as f:
            json.dump({}, f)
        while True:
            newPassword = input("New Client! Create a Password:\n")
            if is_valid_password(newPassword):
                break
            print("Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        password = register_user(newPassword)
        files_folder= "file_vault"
        
        if not os.path.exists("file_vault"):
            files_folder = Path("file_vault")
            files_folder.mkdir(parents=True, exist_ok=True)
        
        generate_self_cert(password)
        generate_uid()
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

    peer_file_db = "peerfiles.json"
    if not os.path.exists(peer_file_db):
        with open(peer_file_db, "w") as f:
            json.dump({}, f)
    
    revoked_keys_db = "revoked.json"
    if not os.path.exists(revoked_keys_db):
        with open(revoked_keys_db, "w") as f:
            json.dump({}, f)

def import_files(password, need_path, input_file):
    if need_path == 1:
        input_file = input("Enter original file path: \n")
    else:
        input_file = input_file
    dest_folder = Path("file_vault")
    original_path = Path(input_file)

    if not original_path.exists():
        print("Error: File Not Found!")
        return
    
    dest_path = dest_folder / original_path.name
    shutil.copy2(str(original_path), str(dest_path))
    update_files_list(password)
    encrypt_file(str(dest_path), password)
    print("File Uploaded!\n")
    return

def generate_self_cert(password):
    ca_key, ca_cert = create_root_ca()
    create_server_cert("127.0.0.1", ca_key, ca_cert)
    create_client_cert(ca_key, ca_cert)
    encrypt_file("file_vault/ca.key", password)
    encrypt_file("file_vault/client.key", password)
    encrypt_file("file_vault/server.key", password)


def update_files_list(password):
    onlyfiles = [f for f in listdir("file_vault") if isfile(join("file_vault", f))]
    filtered_files = [f for f in onlyfiles if ".crt" not in f and ".enc" not in f]
    uid = get_uid()
    current = json.loads(open("filedb.json").read())
    for file in filtered_files:
        if file not in current:
            hash = hash_file(f"file_vault/{file}")
            signature = sign_file_hash(hash, password)
            current[file] = {
                "uid": uid,
                "hash": hash,
                "signature": base64.b64encode(signature).decode('utf-8'),
            }
            with open("filedb.json", "w") as f:
                json.dump(current, f, indent=4)

def export_file(password):
    onlyfiles = [f for f in listdir("file_vault") if isfile(join("file_vault", f))]
    filtered_files = [f for f in onlyfiles if not (f.endswith(".crt") or f.endswith(".key.enc"))]
    path = os.path.abspath("file_vault")
    parent_dir = Path(path).parents[1]
    print("Available Files:")
    for i, file in enumerate(filtered_files):
        if ".crt" not in file and ".key" not in file:
            print(f"{i+1}. {file}")
    choice = input("Select a file to export: ")
    if choice.isdigit() and 1 <= int(choice) <= len(onlyfiles):
        selected_file = onlyfiles[int(choice) - 1]
        file_path = os.path.join("file_vault", selected_file)
        try:
            new_file_path = decrypt_file(file_path, password, file_return=1)
        except:
            print("Error decrypting file. Incorrect List Entry?")
            return
        try:
            shutil.move(new_file_path, parent_dir) 
        except Exception as e:
            print(f"Error moving file: {e}")
            return
        print(f"File {selected_file} exported successfully!")
    else:
        print("Invalid choice. Please try again.")
    
    return
    
def generate_uid():
    #returns a unique identifier for the user based on public key truncated to 8 bytes
    with open("file_vault/server.crt", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
        public_key = cert.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        uid = hashlib.sha256(public_key_bytes).hexdigest()[:8]
        with open("uid.txt", "w") as uid_file:
            uid_file.write(uid)

def get_uid():
    #returns the unique identifier for the user
    with open("uid.txt", "r") as uid_file:
        uid = uid_file.read()
    return uid

def is_valid_password(password):
    if (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    ):
        return True
    return False

def read_peer_files():
    with open("peerfiles.json", "r") as f:
        peer_files = json.load(f)
    print("Peer Files:")
    for peer, files in peer_files.items():
        print(f"{peer}: {', '.join(files)}")

def add_to_revoked_keys(uid, public_key_encoded):
    if os.path.exists("revoked.json"):
        with open("revoked.json", "r") as f:
            revoked_keys = json.load(f)
    else:
        revoked_keys = {}
    
    revoked_keys[uid] = public_key_encoded
    with open("revoked.json", "w") as f:
        json.dump(revoked_keys, f, indent=4)

def merge_revoked_list(peer_list):
    if os.path.exists("revoked.json"):
        with open("revoked.json", "r") as f:
            revoked_keys = json.load(f)
    else:
        revoked_keys = {}
    revoked_keys.update(peer_list)
    print("Revoked keys merged successfully.")
    with open("revoked.json", "w") as f:
        json.dump(revoked_keys, f, indent=4)

def is_revoked(peer):
    if os.path.exists("revoked.json"):
        with open("revoked.json", "r") as f:
            revoked_keys = json.load(f)
    
    if peer.get("uid") in revoked_keys:
        print(f"Peer {peer['uid']} is revoked.")
        return True
    revoked = revoked_keys.values()
    if "public_key" in peer and peer["public_key"] in revoked:
        print(f"Peer {peer['uid']} is revoked.")
        return True
    return False

def revoke_entries_by_uid(uid):
    filedb_path = "filedb.json"
    if os.path.exists(filedb_path):
        with open(filedb_path, "r") as f:
            filedb = json.load(f)
    else:
        filedb = {}
    
    for filename in list(filedb.keys()):
        entry = filedb[filename]
        if entry.get("uid") == uid:
            file_path = join("file_vault", filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")
                except Exception as e:
                    print(f"Error deleting {file_path}: {e}")
            enc_file_path = file_path + ".enc"
            if os.path.exists(enc_file_path):
                try:
                    os.remove(enc_file_path)
                    print(f"Deleted encrypted file: {enc_file_path}")
                except Exception as e:
                    print(f"Error deleting {enc_file_path}: {e}")
            del filedb[filename]
    
    with open(filedb_path, "w") as f:
        json.dump(filedb, f, indent=4)

    peerfiles_path = "peerfiles.json"
    if os.path.exists(peerfiles_path):
        with open(peerfiles_path, "r") as f:
            peerfiles = json.load(f)
        for peer_name in list(peerfiles.keys()):
            files = peerfiles[peer_name]
            for file_key in list(files.keys()):
                if files[file_key].get("uid") == uid:
                    del files[file_key]
                    print(f"Removed file entry '{file_key}' for peer '{peer_name}'.")
            if not files:
                del peerfiles[peer_name]
        with open(peerfiles_path, "w") as f:
            json.dump(peerfiles, f, indent=4)
    else:
        print("peerfiles.json not found.")

    peers_path = "peers.json"
    if os.path.exists(peers_path):
        with open(peers_path, "r") as f:
            peers = json.load(f)
        for peer_name in list(peers.keys()):
            if peers[peer_name].get("uid") == uid:
                del peers[peer_name]
                print(f"Removed peer '{peer_name}' with uid {uid}.")
        with open(peers_path, "w") as f:
            json.dump(peers, f, indent=4)
    else:
        print("peers.json not found.")