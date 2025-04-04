from sender import *
from reciever import *
from filemanager import *
from login import *

import os

def main():


    password = create_user_file()
    password = login()
    create_data_files()
    stop_event = threading.Event()
    zeroconf = joinNetwork(stop_event)
    start_tls_server_thread(password, stop_event)
    while True:
        
        print("Welcome to SecureShare V1.0. Please select an action to continue:\n"
            "\n"
            "1. View Available Files\n"
            "2. Interact With Peer\n"
            "3. Upload A File\n"
            "4. Export A File\n"
            "5. Add A Peer\n"
            "6. Quit\n")
        

        action = input("Enter action: \n")

        if action == "1":
            read_peer_files()
        elif action == "2":
            message_peer(password)
        elif action == "3":
            import_files(password, 1, None)
        elif action == "4":
            export_file(password)
        elif action == "5":
            discover_peers(zeroconf)
        elif action == "6":
            stop_event.set()
            exit()
        else:
            print("invalid input!\n")

if __name__ == "__main__":
    main()