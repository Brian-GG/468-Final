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

        address = peer["address"][0], 3000
        sock = socket.create_connection(address)
        conn = SSL.Connection(context, sock)
        conn.set_connect_state()
        conn.do_handshake()

        conn.send(json.dumps(message).encode())
        response = conn.recv(4096).decode()
        handle_response(response, message, password)
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
                if peers_hash not in [peer["public_key_hash"] for peer in trusted_peers.values()]:
                    print("Untrusted peer! Closing connection.")
                    conn.close()
                    continue
                print("handling connection")
                handle_client_connection(conn, password)

            except SSL.Error as e:
                print(f"TLS handshake failed: {e}")
                conn.close()

    except Exception as e:
        print(f"Error starting TLS server: {e}")


def add_trusted_peer(peer):
    try:
        if os.path.exists("peers.json"):
            with open("peers.json", "r") as f:
                trusted_peers = json.load(f)
        else:
            trusted_peers = {}

        trusted_peers[peer["name"]] = {
            "name": peer["name"],
            "address": peer["addresses"],
            "public_key_hash": peer["public_key_hash"],
        }

        with open("peers.json", "w") as f:
            json.dump(trusted_peers, f, indent=4)
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
            return list(files.keys())
    return []

def request_file(peer, password, filename):
    try:
        message = {"type": "REQUEST_FILE", "data": {"filename": filename}}
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

def handle_client_connection(conn, password):
    try:
        data = conn.recv(4096).decode()
        request = json.loads(data)
        req_type = request.get("type")
        print(req_type)
        
        if req_type == "LIST_FILES":
            response = list_available_files()
            conn.send(json.dumps(response).encode())

        elif req_type == "REQUEST_FILE":
            peer_cert = conn.get_certificate()
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, peer_cert)
            filename = request.get("data", {}).get("filename")
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
                            conn.send(json.dumps({"message": "File not found in database."}).encode())
                            return
                    else:
                        conn.send(json.dumps({"message": "File database not found."}).encode())
                        return

                    # Send the file data, hash, and signature
                    response = {
                        "filename": filename,
                        "file_data": file_data.hex(),
                        "hash": file_hash,
                        "signature": file_signature,
                        "uid": uid,
                        "certificate": cert_pem
                    }
                    conn.send(json.dumps(response).encode())
                else:
                    conn.send(json.dumps({"message": "File transfer declined."}).encode())
        
        elif req_type == "SEND_FILE":
            filename = request.get("data", {}).get("filename")
            consent = input(f"Accept file {filename}? (yes/no): ")
            if consent.lower() == "yes":
                conn.send(json.dumps({"message": "File transfer accepted."}).encode())
                file_data = bytes.fromhex(request.get("data", {}).get("file_data"))
                file_hash = request.get("data", {}).get("hash")
                uid = request.get("data", {}).get("uid")
                decoded_hash = base64.urlsafe_b64decode(file_hash)
                file_signature = base64.b64decode(request.get("data", {}).get("signature"))
                print(f"{decoded_hash}\n")
                print(f"{file_hash}\n")
                print(f"{hashlib.sha256(file_data).digest()}\n")
                if hashlib.sha256(file_data).digest() == decoded_hash:
                    public_key_pem = conn.get_peer_certificate().get_pubkey().to_cryptography_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    public_key = serialization.load_pem_public_key(public_key_pem)
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
                        conn.send(json.dumps({"message": "Signature verification failed. Transfer failed."}).encode())
                else:
                    conn.send(json.dumps({"message": "Integrity check failed. Transfer failed."}).encode())
            else:
                conn.send(json.dumps({"message": "File transfer declined."}).encode())

        conn.close()
    except Exception as e:
        print(f"Error handling client connection: {e}")
        conn.close()

def handle_response(response, message, password):
    try:
        response_data = json.loads(response)

        if message["type"] == "LIST_FILES":
            print("Available files:")
            for file in response_data:
                print(f"- {file}")
            peer_name = message.get("peer_name", "Unknown Peer")
            if os.path.exists("peerfiles.json"):
                with open("peerfiles.json", "r") as f:
                    peer_files = json.load(f)
            else:
                peer_files = {}

            peer_files[peer_name] = response_data

            with open("peerfiles.json", "w") as f:
                json.dump(peer_files, f, indent=4)
            print(f"File list from {peer_name} saved to peerfiles.json.")

        elif message["type"] == "REQUEST_FILE":
            if "file_data" in response_data:
                filename = response_data["filename"]
                file_data = bytes.fromhex(response_data["file_data"])
                file_hash = response_data["hash"]
                decoded_hash = base64.urlsafe_b64decode(file_hash)
                file_signature = base64.b64decode(response_data["signature"])
                uid = response_data["uid"]

                if hashlib.sha256(file_data).digest() == decoded_hash:
                    print(f"File '{filename}' passed integrity check.")

                    cert_pem = response_data.get("certificate")
                    peer_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem.encode())
                    public_key = peer_cert.get_pubkey().to_cryptography_key()
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
            print(response)

        else:
            print(f"Unexpected response: {response}")

    except json.JSONDecodeError:
        print(f"Invalid response received: {response}")