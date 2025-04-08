from OpenSSL import crypto, SSL
from cryptography.hazmat.primitives import serialization
import socket
import json
import threading
import os
import hashlib
from encryption import *
from filemanager import *

def create_tls_connection(peer, password, message):
    try:

        with open("file_vault/client.crt", "rb") as f:
            client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        decrypted_key_data = decrypt_file("file_vault/client.key.enc", password, 0)
        client_key = crypto.load_privatekey(crypto.FILETYPE_PEM, decrypted_key_data)

        with open("file_vault/ca.crt", "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.use_certificate(client_cert)
        context.use_privatekey(client_key)
        context.load_verify_locations("file_vault/ca.crt")
        context.set_verify(SSL.VERIFY_PEER, lambda conn, cert, errno, depth, ok: ok)

        address = peer["address"], 3000
        sock = socket.create_connection(address)
        conn = SSL.Connection(context, sock)
        conn.set_connect_state()
        conn.do_handshake()

        send_message(conn, message)
        handle_response(conn, message, password)
        conn.close()

    except Exception as e:
        print(f"TLS connection failed: {e}")

def start_tls_server(password, stop_event):
    try:
        with open("file_vault/server.crt", "rb") as f:
            server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        decrypted_key_data = decrypt_file("file_vault/server.key.enc", password, 0)
        server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, decrypted_key_data)

        with open("peers.json", "r") as f:
            trusted_peers = json.load(f)

        context = SSL.Context(SSL.TLS_SERVER_METHOD)
        context.use_certificate(server_cert)
        context.use_privatekey(server_key)
        context.load_verify_locations("file_vault/ca.crt")
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda conn, cert, errno, depth, ok: ok)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", 3000))
        sock.listen(5)

        while not stop_event.is_set():
            client_sock, addr = sock.accept()
            conn = SSL.Connection(context, client_sock)
            conn.set_accept_state()
            try:
                conn.do_handshake()
                print(f"TLS handshake successful with {addr}")
                client_cert = conn.get_peer_certificate()
                public_key = client_cert.get_pubkey()
                public_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
                peers_hash = hashlib.sha256(public_key_pem).hexdigest()
                print("handling connection")
                handle_client_connection(conn, password)

            except SSL.Error as e:
                print(f"TLS handshake failed: {e}")
                conn.close()

    except Exception as e:
        print(f"Error starting TLS server: {e}")


def add_trusted_peer(peer, password):
    try:
        if os.path.exists("peers.json"):
            with open("peers.json", "r") as f:
                trusted_peers = json.load(f)
        else:
            trusted_peers = {}
        get_peer_info(peer, password)
    except Exception as e:
        print(f"Failed to add peer to trusted list: {e}")

def message_peer(password):
    try:
        if os.path.exists("peers.json"):
            with open("peers.json", "r") as f:
                trusted_peers = json.load(f)
            peer_list = list(trusted_peers.keys())
            print("Available peers:")
            for i, peer in enumerate(peer_list):
                print(f"{i + 1}. {peer}")
            choice = int(input("Choose a peer: ")) - 1
            if 0 <= choice < len(peer_list):
                selected_peer = trusted_peers[peer_list[choice]]
                print("\nAvailable operations:")
                print("1. LIST_FILES")
                print("2. SEND_FILE")
                print("3. REQUEST_FILE")
                operation = int(input("Choose an operation: "))

                if operation == 1:
                    create_tls_connection(selected_peer, password, {"type": "LIST_FILES", "data": {}})
                elif operation == 2:
                    filename = input("Enter the filename to send: ")
                    send_file(selected_peer, password, filename)
                elif operation == 3:
                    filename = input("Enter the filename to request: ")
                    request_file(selected_peer, password, filename)
                else:
                    print("Invalid operation selected.")
            else:
                print("Invalid peer selection.")
        else:
            print("No peers available.")
    except Exception as e:
        print(f"Error choosing peer: {e}")
    return None

def start_tls_server_thread(password, stop_event):
    server_thread = threading.Thread(target=start_tls_server, args=(password, stop_event), daemon=True)
    server_thread.start()

def list_available_files():
    if os.path.exists("filedb.json"):
        with open("filedb.json", "r") as f:
            files = json.load(f)
            return files
    return []

def request_file(peer, password, filename):
    try:
        message = {"type": "REQUEST_FILE", "data": {"fileName": filename, "peerName": f"SecureShareP2P-{socket.gethostname()}"}}
        create_tls_connection(peer, password, message)
    except Exception as e:
        print(f"Failed to retrieve file from {peer['name']}: {e}")
        print("Searching for other peers with the same file...")

        if os.path.exists("peerfiles.json"):
            with open("peerfiles.json", "r") as f:
                peer_files = json.load(f)

            file_hash = None
            for peer_name, files in peer_files.items():
                if filename in files:
                    file_hash = files[filename]["hash"]
                    break

            if file_hash:
                for peer_name, files in peer_files.items():
                    if peer_name != peer["name"]:
                        for file, metadata in files.items():
                            if metadata["hash"] == file_hash:
                                print(f"Found file '{filename}' with matching hash on peer '{peer_name}'.")
                                new_peer = {
                                    "name": peer_name,
                                    "address": peer_files[peer_name]["address"]
                                }
                                try:
                                    create_tls_connection(new_peer, password, message)
                                    return
                                except Exception as e:
                                    print(f"Failed to retrieve file from {peer_name}: {e}")
            else:
                print(f"No other peers found with the file '{filename}'.")
        else:
            print("peerfiles.json not found. Unable to search for other peers.")

def send_file(peer, password, filename):
    file_path = os.path.join("file_vault", filename)
    tmp_filename, _ = os.path.splitext(filename)
    if os.path.exists(file_path):
        file_data = decrypt_file(file_path, password, 0)
        # file_hash = hashlib.sha256(file_data).hexdigest()
    
        if os.path.exists("filedb.json"):
            with open("filedb.json", "r") as f:
                filedb = json.load(f)
                if tmp_filename in filedb:
                    file_hash = filedb[tmp_filename]["hash"]
                    file_signature = filedb[tmp_filename]["signature"]
                    uid = filedb[tmp_filename]["uid"]
                else:
                    print("File not found in database")
                    return
        else:
            print("File database not found")
            return

        message = {"type": "SEND_FILE", "data" : {"filename": tmp_filename, "file_data": file_data.hex(), "hash": file_hash, "signature": file_signature, "uid": uid}}
        create_tls_connection(peer, password, message)

    else:
        print("File not found")

def sync_revoked_keys(password):
    with open("revoked.json", "r") as f:
        revoked_keys = json.load(f)
    with open("peers.json", "r") as f:
        trusted_peers = json.load(f)
    
    for peer in trusted_peers.values():
        try:
            message = {"type": "SYNC_REVOKED", "data": revoked_keys}
            create_tls_connection(peer, password, message)
        except Exception as e:
            print(f"Failed to sync revoked keys with {peer['name']}: {e}")


def get_peer_info(peer, password):
    try:
        service_name = f"SecureShareP2P-{socket.gethostname()}._secureshare._tcp.local."
        message = {"type": "PEER_CONNECTED", "data": { "peerName": f"{service_name}" }}
        create_tls_connection(peer, password, message)
    except Exception as e:
        print(f"Failed to retrieve public key from {peer['name']}: {e}")
        return None

def handle_client_connection(conn, password):
    try:
        
        is_peer_trusted = False

        client_cert = conn.get_peer_certificate().get_pubkey().to_cryptography_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        client_key_encoded = base64.b64encode(client_cert).decode('utf-8')
        if os.path.exists("peers.json"):
            with open("peers.json", "r") as f:
                trusted_peers = json.load(f)
            for peer in trusted_peers.values():
                keystr = peer["public_key"]
                if keystr == client_key_encoded:
                    is_peer_trusted = True
                    break
        else:
            trusted_peers = {}
        


        request = recieve_message(conn)
        req_type = request.get("type")
        client_ver = request.get("client")
        if client_ver == "js":
            request = convert_from_js_msg(request)
            req_type = request.get("type")
        print(req_type)

        if req_type == "SYNC_REVOKED":
            if not is_peer_trusted:
                print("Peer is not trusted. Cannot sync revoked list.")
                conn.close()
                return
            
            try:
                revoked_keys = request.get("data")
                merge_revoked_list(revoked_keys)

                with open("revoked.json", "r") as f:
                    revoked_local_keys = json.load(f)
                for uid in revoked_keys:
                    revoke_entries_by_uid(uid)
                response = {"message": revoked_local_keys}
                send_message(conn, response)
            except Exception as e:
                print(f"Failed to merge revoked keys: {e}")

        elif req_type == "MIGRATION":
            migration_data = request.get("data")
            old_uid = migration_data.get("old_uid")
            new_uid = migration_data.get("new_uid")
            old_public_key = migration_data.get("old_public_key")
            new_public_key = migration_data.get("new_public_key")
            signature = base64.b64decode(migration_data.get("signature"))

            public_key_bytes = base64.b64decode(old_public_key)
            public_key = serialization.load_pem_public_key(public_key_bytes)
            data_to_verify = {k: migration_data[k] for k in migration_data if k != "signature"}

            try:
                public_key.verify(signature, json.dumps(data_to_verify, sort_keys=True).encode('utf-8'))
                print(f"Migration data verified successfully. Old UID: {old_uid}, New UID: {new_uid}")

                add_to_revoked_keys(old_uid, old_public_key)
                revoke_entries_by_uid(old_uid)

            except Exception as e:
                print(f"Signature verification failed: {e}")
                response = {"message": "Signature verification failed. Migration failed."}
                send_message(conn, response)
                return
            response = {"message": "Migration successful."}
            send_message(conn, response)

        elif req_type == "REQUEST_PUBLIC_KEY":
            with open("file_vault/client.crt", "rb") as f:
                client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            public_key = client_cert.get_pubkey().to_cryptography_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            public_key_encoded = base64.b64encode(public_key).decode('utf-8')
            uid = get_uid()
            service_name = f"SecureShareP2P-{socket.gethostname()}._secureshare._tcp.local."
            hostname = socket.gethostname()
            adddress = socket.gethostbyname(hostname)
            response = {
                "type": "WELCOME",
                  "data": {        
                    "public_key": public_key_encoded,
                    "uid": uid,
                    "name": service_name,
                    "address": adddress
                    }
                }
            send_message(conn, response)

        elif req_type == "LIST_FILES":
            if not is_peer_trusted:
                print("Peer is not trusted. Cannot list files.")
                conn.close()
                return
            
            service_name = f"SecureShareP2P-{socket.gethostname()}._secureshare._tcp.local."
            response = {"type": "FILES_LIST", "name": service_name, "data": { "files": list_available_files()}}
            send_message(conn, response)

        elif req_type == "REQUEST_FILE":
            if not is_peer_trusted:
                print("Peer is not trusted. Cannot request files.")
                conn.close()
                return
            
            peername = request.get("data", {}).get("peerName")
            filename = request.get("data", {}).get("fileName")
            tmp_filename = filename + ".enc"
            file_path = os.path.join("file_vault", tmp_filename)
            if filename in list_available_files():
                consent = input(f"file {filename} requested. Do you want to send it? (yes/no): ")
                if consent.lower() == "yes":
                    file_data = decrypt_file(file_path, password, 0)

                    # Retrieve the file's signature from filedb.json
                    if os.path.exists("filedb.json"):
                        with open("filedb.json", "r") as f:
                            filedb = json.load(f)
                        if filename in filedb:
                            file_hash = filedb[filename]["hash"]
                            file_signature = filedb[filename]["signature"]
                            uid = filedb[filename]["uid"]
                        else:
                            response = {"message": "File not found in database."}
                            send_message(conn, response)
                            return
                    else:
                        response = {"message": "File database not found."}
                        send_message(conn, response)
                        return

                    with open("file_vault/client.crt", "rb") as f:
                        client_cert = f.read()
                    encoded_cert = base64.b64encode(client_cert).decode('utf-8')
                    # Send the file data, hash, and signature
                    response = {
                        "type"
                        "filename": filename,
                        "file_data": file_data.hex(),
                        "hash": file_hash,
                        "signature": file_signature,
                        "uid": uid,
                        "certificate": encoded_cert
                    }
                    send_message(conn, response)
                else:
                    response = {"message": "File transfer declined."}
                    send_message(conn, response)
            else:
                response = {"message": "File not found."}
                send_message(conn, response)

        elif req_type == "SEND_FILE":
            if not is_peer_trusted:
                print("Peer is not trusted. Cannot send files.")
                conn.close()
                return

            filename = request.get("data", {}).get("filename")
            consent = input(f"Accept file {filename}? (yes/no): ")
            if consent.lower() == "yes":
                response = {"message": "File transfer accepted."}
                send_message(conn, response)
                file_data = bytes.fromhex(request.get("data", {}).get("file_data"))
                file_hash = request.get("data", {}).get("hash")
                uid = request.get("data", {}).get("uid")
                decoded_hash = base64.urlsafe_b64decode(file_hash)
                file_signature = base64.b64decode(request.get("data", {}).get("signature"))
                if hashlib.sha256(file_data).hexdigest() == file_hash:
                    public_key_encoded = get_public_key_by_uid(uid)
                    if public_key_encoded is None:
                        response = {"message": "File Creator Not A Trusted Peer."}
                        send_message(conn, response)
                    public_key_bytes = base64.b64decode(public_key_encoded)
                    public_key = serialization.load_pem_public_key(public_key_bytes)
                    print(type(public_key))
                    try:
                        public_key.verify(
                            file_signature,
                            file_hash.encode(),
                        )
                        file_path = os.path.join("file_vault", filename)
                        with open(file_path, "wb") as f:
                            f.write(file_data)

                        # Encrypt the file
                        encrypt_file(file_path, password)
                        # Add file info to filedb.json
                        if os.path.exists("filedb.json"):
                            with open("filedb.json", "r") as f:
                                filedb = json.load(f)
                        else:
                            filedb = {}

                        filedb[filename] = {
                            "uid": uid,
                            "hash": file_hash,
                            "signature": base64.b64encode(file_signature).decode('utf-8'),
                        }
                        with open("filedb.json", "w") as f:
                            json.dump(filedb, f, indent=4)
                        print(f"File '{filename}' saved, encrypted, and added to filedb.json.")
                    except Exception as e:
                        print(f"Signature verification failed: {e}")
                        response = {"message": "Signature verification failed. Transfer failed."}
                        send_message(conn, response)
                else:
                    print("File hash mismatch! transfer failed.")
                    response = {"message": "Integrity check failed. Transfer failed."}
                    send_message(conn, response)
            else:
                response = {"message": "File transfer declined."}
                send_message(conn, response)

        conn.close()
    except Exception as e:
        print(f"Error handling client connection: {e}")
        conn.close()

def handle_response(conn, message, password):
    try:
        response_data = recieve_message(conn)
        if response_data["type"] == "SYNC_REVOKED":
            try:
                revoked_keys = response_data["message"]
                print(f"Revoked keys received: {revoked_keys}")
                merge_revoked_list(revoked_keys)
            except Exception as e:
                print(f"Failed to merge revoked keys: {e}")
        
        elif message["type"] == "WELCOME" or message["type"] == "REQUEST_PUBLIC_KEY":
            public_key = response_data["data"]["public_key"]
            uid = response_data["data"]["uid"]
            peer_name = response_data["data"]["name"]
            peer_address = response_data["data"]["address"]
            print(f"Peer info recieived from {peer_name}:")

            try:
                if os.path.exists("peers.json"):
                    with open("peers.json", "r") as f:
                        trusted_peers = json.load(f)
                else:
                    trusted_peers = {}

                trusted_peers[peer_name] = {
                    "name": peer_name,
                    "address": peer_address,
                    "public_key": public_key,
                    "uid": uid,
                }    
                
                with open("peers.json", "w") as f:
                    json.dump(trusted_peers, f, indent=4)
            except Exception as e:
                print(f"Failed to save peer info: {e}")

        elif response_data["type"] == "FILES_LIST":
            print("Available files:")
            print(response_data["data"]["files"])
            peer_name = response_data["data"]["name"]
            if os.path.exists("peerfiles.json"):
                with open("peerfiles.json", "r") as f:
                    peer_files = json.load(f)
            else:
                peer_files = {}

            peer_files[peer_name] = response_data["data"]["files"]

            with open("peerfiles.json", "w") as f:
                json.dump(peer_files, f, indent=4)
            print(f"File list from {peer_name} saved to peerfiles.json.")

        elif response_data["type"] == "FILE_TRANSFER":
            if "fileContent" in response_data["data"]:
                filename = response_data["data"]["fileName"]
                file_data = bytes.fromhex(response_data["data"]["fileContent"])
                file_hash = response_data["data"]["fileHash"]
                file_signature = response_data["data"]["fileSignature"]
                uid = response_data["data"]["uid"]

                if hashlib.sha256(file_data).hexdigest() == file_hash:
                    print(f"file_signature type: {type(file_signature)}")
                    print(f"File '{filename}' passed integrity check.")
                    public_key_encoded = get_public_key_by_uid(uid)
                    if public_key_encoded is None:
                        response = {"message": "File Creator Not A Trusted Peer."}
                        send_message(conn, response)
                    public_key_bytes = base64.b64decode(public_key_encoded)
                    public_key = serialization.load_pem_public_key(public_key_bytes)
                    if response_data["client"] == "js":
                        file_signature = file_signature.encode()
                    try:
                        public_key.verify(
                            file_signature,
                            file_hash.encode(),
                        )
                        file_path = os.path.join("file_vault", filename)
                        with open(file_path, "wb") as f:
                            f.write(file_data)

                        # Encrypt the file
                        encrypt_file(file_path, password)

                        # Add file info to filedb.json
                        if os.path.exists("filedb.json"):
                            with open("filedb.json", "r") as f:
                                filedb = json.load(f)
                        else:
                            filedb = {}

                        filedb[filename] = {
                            "uid": uid,
                            "hash": file_hash,
                            "signature": base64.b64encode(file_signature).decode('utf-8'),
                        }

                        with open("filedb.json", "w") as f:
                            json.dump(filedb, f, indent=4)

                        print(f"File '{filename}' saved, encrypted, and added to filedb.json.") 
                    except Exception as e:
                        print(f"Signature verification failed: {e}")
                else:
                    print("File hash mismatch. Transfer failed.")
            else:
                print("File transfer declined or failed.")

        elif message["type"] == "SEND_FILE":
            print(response_data)
        
        elif message["type"] == "MIGRATION":
            print(response_data)

        else:
            print(f"Unexpected response: {response_data}")

    except json.JSONDecodeError:
        print(f"Invalid response received: {response_data}")

def send_message(conn, message):
    message["client"] = "py"
    print(f"Sending message: {message}")
    message_encoded = json.dumps(message).encode()
    conn.sendall(message_encoded + b'---DELIMITER---')
    return

def recieve_message(conn):
    message = recieve_data(conn)
    if not message:
        return None
    return json.loads(message.decode('utf-8'))

def recieve_data(conn):
    data = b""
    try:
        while True:
            chunk = conn.recv(4096)
            print(chunk)
            if not chunk:
                break
            data += chunk
            if b'---DELIMITER---' in data:
                data = data.split(b'---DELIMITER---')[0]
                break
    except ConnectionResetError:
        print("Connection reset by peer")
        return None
    return data

def get_public_key_by_uid(uid):
    with open("peers.json", "r") as f:
        peers = json.load(f)
    for peer_info in peers.values():
        if peer_info.get("uid") == uid:
            return peer_info.get("public_key")
    return None

def convert_from_js_msg(message):
    if message.get("type") == "PEER_CONNECTED":
        return {
            "type": "REQUEST_PUBLIC_KEY",
            "data": {
                "public_key": message.get("publicKey"),
                "keyRevocationList": message.get("KeyRevocationList"),
            }
        }

def revoke_certificate(password):
    old_uid = get_uid()
    with open("file_vault/client.crt", "rb") as f:
        old_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    old_public_key_bytes = old_cert.get_pubkey().to_cryptography_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    old_public_key_encoded = base64.b64encode(old_public_key_bytes).decode('utf-8')

    decrypted_key_data = decrypt_file("file_vault/client.key.enc", password, 0)
    old_private_key_obj = serialization.load_pem_private_key(decrypted_key_data, password=None)

    generate_self_cert(password)
    generate_uid()

    new_uid = get_uid()
    with open("file_vault/client.crt", "rb") as f:
        new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    new_public_key_bytes = new_cert.get_pubkey().to_cryptography_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    new_public_key_encoded = base64.b64encode(new_public_key_bytes).decode('utf-8')

    migration_data = {
        "old_uid": old_uid,
        "new_uid": new_uid,
        "old_public_key": old_public_key_encoded,
        "new_public_key": new_public_key_encoded,
    }

    migration_data_str = json.dumps(migration_data, sort_keys=True)

    signature = old_private_key_obj.sign(migration_data_str.encode('utf-8'))
    migration_data["signature"] = base64.b64encode(signature).decode('utf-8')

    migration_message = {
        "type": "MIGRATION",
        "data": migration_data
    }

    if os.path.exists("peers.json"):
        with open("peers.json", "r") as f:
            trusted_peers = json.load(f)
        
        for peer_info in trusted_peers.values():
            if is_revoked(peer_info):
                print("Skipping revoked peer")
                continue
            try:
                create_tls_connection(peer_info, password, migration_message)
                print("Sent migration message to peer")
            except Exception as e:
                print(f"Failed to send migration message to {peer_info}: {e}")
    else:
        print("No peers found to send migration message to.")
    
    add_to_revoked_keys(old_uid, old_public_key_encoded)
    revoke_entries_by_uid(old_uid)
    print("Certificate revoked successfully.")
         