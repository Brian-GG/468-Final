from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes, ServiceInfo
from time import sleep
from typing import cast
import socket
import threading

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
        properties={"secure": "true", "version": "1.0"},
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

    return

