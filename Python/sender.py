import ssl
import socket
import json
import io
import os
from encryption import decrypt_file

def create_tls_connection(peer, password):
    try:
        
        with open("file_vault/client.crt", "rb") as f:
            certificate_data = f.read()
                
        decrypted_key_data = decrypt_file("file_vault/client.key.enc", password, 0)

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile=io.BytesIO(certificate_data), 
            keyfile=io.BytesIO(decrypted_key_data)
        )
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection(peer["address"], 3000) as sock:
            with context.wrap_socket(sock, server_hostname=peer["name"]) as tls_sock:
                print(f"Secure connection established with {peer['name']}")
                return True
    except Exception as e:
        print(f"TLS connection failed: {e}")
        return False

def start_tls_server(password):
    try:
        # Decrypt the private key
        decrypted_key_data = decrypt_file("file_vault/server.key.enc", password, 0)

        # Create an SSL context for the server
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile="file_vault/server.crt",
            keyfile=io.BytesIO(decrypted_key_data)
        )
        context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate


        context.load_verify_locations(cafile="file_vault/ca.crt")  # Load CA certificate for client verification

        # Create a server socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_socket:
            server_socket.bind(("0.0.0.0", 3000))  # Listen on all interfaces, port 3000
            server_socket.listen(5)  # Allow up to 5 pending connections
            print("TLS server is listening on port 3000...")

            while True:
                # Accept an incoming connection
                client_socket, client_address = server_socket.accept()
                print(f"Connection from {client_address}")

                # Wrap the socket with TLS
                try:
                    with context.wrap_socket(client_socket, server_side=True) as tls_socket:
                        print("TLS handshake successful.")
                        print(f"Client certificate: {tls_socket.getpeercert()}")

                        # Handle the secure connection
                        handle_client_connection(tls_socket)
                except ssl.SSLError as e:
                    print(f"TLS handshake failed: {e}")
    except Exception as e:
        print(f"Error starting TLS server: {e}")

def handle_client_connection(tls_socket):
    try:
        # Receive data from the client
        data = tls_socket.recv(1024).decode("utf-8")
        print(f"Received: {data}")

        # Send a response to the client
        response = "Hello, secure client!"
        tls_socket.send(response.encode("utf-8"))
    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        tls_socket.close()

def add_trusted_peer(peer):
    try:
        if os.path.exists("peers.json"):
            with open("peers.json", "r") as f:
                trusted_peers = json.load(f)
        else:
            trusted_peers = {}

        trusted_peers[peer["name"]] = {
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
