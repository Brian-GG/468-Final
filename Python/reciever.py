from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes, ServiceInfo
from time import sleep
from typing import cast
from sender import add_trusted_peer
import socket
import threading
import base64
import hashlib
import json
import os

target_port = 3000

class Listener(ServiceListener):
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is None:
            print(f"Could not get details for {name}. The service may not be available")
            return
        if info and info.port == target_port:
            print(f"Service {name} updated")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is None:
            print(f"Could not get details for {name}. The service may not be available")
            return
        if info and info.port == target_port:
            print(f"Service {name} removed")

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is None:
            print(f"Could not get details for {name}. The service may not be available")
            return
        if info and info.port == target_port:
            addresses = [f"{addr}:{cast(int, info.port)}" for addr in info.parsed_scoped_addresses()]
            print(f"Service {name} added, service info:")
            print(f"  Addresses: {', '.join(addresses)}")
            print(f"  Server: {info.server}\n")

def joinNetwork():
    zeroconf = Zeroconf()
    listener = Listener()
    services = list(ZeroconfServiceTypes.find(zc=zeroconf))

    public_key = base64.b64encode(load_public_key()).decode("utf-8")
    public_key_hash = hashlib.sha256(public_key.encode()).hexdigest()
    print(f"Public Key Hash: {public_key_hash}")
    service_type = "_secureshare._tcp.local."
    service_name = f"SecureShareP2P-{socket.gethostname()}._secureshare._tcp.local."
    port = 3000

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    myInfo = ServiceInfo(
        type_=service_type,
        name=service_name,
        port=port,
        addresses=[socket.inet_aton(local_ip)],
        properties={"public_key": public_key, "version": "1.0"},
    )

    print(f"\nBrowsing {len(services)} service(s)\n")
    browser = ServiceBrowser(zeroconf, services, listener)
    print("Registration of a service\n")
    zeroconf.register_service(myInfo)
    stop_event = threading.Event()

    def keep_running():
            try:
                stop_event.wait()
            except KeyboardInterrupt:
                print("\nExiting...")
                stop_event.set()
                zeroconf.close()
    thread = threading.Thread(target=keep_running, daemon=True)
    thread.start()

    return zeroconf

def discover_peers(zeroconf, password):
    
    if os.path.exists("peers.json"):
        with open("peers.json", "r") as f:
            trusted_peers = json.load(f)
    else:
        trusted_peers = {}
    
    
    services = list(ZeroconfServiceTypes.find(zc=zeroconf))
    discovered_peers = []
    for service in services:
        info = zeroconf.get_service_info("_secureshare._tcp.local.", service)
        if info is None:
            print("No peers found")
            return
        if info and info.port == target_port:
            addresses = [addr for addr in info.parsed_scoped_addresses()]
            public_key = info.properties.get(b"public_key")
            public_key_hash = hashlib.sha256(public_key).hexdigest()
            peer_info = {
                "name": service,
                "addresses": addresses,
                "public_key": public_key.decode("utf-8"),
                "public_key_hash": public_key_hash,
            }
            
            if peer_info["name"] in trusted_peers:
                print(f"Peer {peer_info['name']} is already trusted.")
                continue
            discovered_peers.append(peer_info)
            print(f"{len(discovered_peers)}. Hostname: {peer_info['hostname']}, Address: {peer_info['address']}, Public Key Hash: {peer_info['public_key_hash']}")
    if not discovered_peers:
        print("No peers discovered.")
        return None
    
    choice = input("\nEnter the number of the peer you wish to connect to: ")
    if choice.isdigit() and 1 <= int(choice) <= len(discovered_peers):
        selected_peer = discovered_peers[int(choice) - 1]
        print(f"\nYou selected: {selected_peer['hostname']} ({selected_peer['address']})")
        print(f"Peer's Public Key Hash: {selected_peer['public_key_hash']}\n")
        print("Please verify the public key hash with the peer before proceeding.")
        confirm = input("Do you trust this peer? (yes/no): ").strip().lower()
        if confirm == "yes":
            add_trusted_peer(selected_peer)
            print(f"Peer {selected_peer['hostname']} added to trusted peers.")
            return None
        else:
            print("Peer not trusted. Skipping.")
            return None
    else:
        print("Invalid selection.")
        return None

def load_public_key():
    with open("file_vault/certificate.pem", "rb") as f:
        public_key = f.read()
        return public_key