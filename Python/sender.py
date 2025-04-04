from OpenSSL import crypto, SSL
import socket
import json
import threading
import os
import hashlib
from encryption import decrypt_file

def create_tls_connection(peer, password):
    try:
        # Load cert and decrypted key from memory
        with open("file_vault/client.crt", "rb") as f:
            client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        decrypted_key_data = decrypt_file("file_vault/client.key.enc", password, 0)
        client_key = crypto.load_privatekey(crypto.FILETYPE_PEM, decrypted_key_data)

        # Load CA cert
        with open("file_vault/ca.crt", "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # Create SSL context
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

        peer_name = peer.get("name", "Unknown Peer")
        print(f"Secure connection established with {peer_name}")
        conn.send(b"Hello from client")
        print(conn.recv(1024).decode())
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

        print("TLS server is listening on port 3000...")

        while not stop_event.is_set():
            client_sock, addr = sock.accept()
            conn = SSL.Connection(context, client_sock)
            conn.set_accept_state()
            try:
                conn.do_handshake()
                print(f"TLS handshake successful with {addr}")
                client_cert = conn.get_peer_certificate()
                public_key = client_cert.get_pubkey()
                print(f"rawkey: {public_key}")
                public_key_asn1 = crypto.dump_publickey(crypto.FILETYPE_ASN1, public_key)
                peers_hash = hashlib.sha256(public_key_asn1).hexdigest()
                print(f"Peer's public key bruh2: {peers_hash}")
                if peers_hash not in [peer["public_key_hash"] for peer in trusted_peers.values()]:
                    print("Untrusted peer! Closing connection.")
                    conn.close()
                    continue

                data = conn.recv(1024).decode("utf-8")
                print(f"Received: {data}")
                conn.send(b"Hello, secure client!")
                conn.shutdown()
                conn.close()

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
                create_tls_connection(selected_peer, password)
            else:
                print("Invalid choice.")
        else:
            print("No peers available.")
    except Exception as e:
        print(f"Error choosing peer: {e}")
    return None

def start_tls_server_thread(password, stop_event):
    server_thread = threading.Thread(target=start_tls_server, args=(password, stop_event), daemon=True)
    server_thread.start()