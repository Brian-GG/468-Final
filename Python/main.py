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
    sync_revoked_keys(password)
    while True:
        try:
            print("Welcome to SecureShare V1.0. Please select an action to continue:\n"
                "\n"
                "1. View Available Files\n"
                "2. Interact With Peer\n"
                "3. Upload A File\n"
                "4. Export A File\n"
                "5. Add A Peer\n"
                "6. Quit\n"
                "7. Listen For Requests\n"
                "8. Revoke Certificate\n")
            

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
                discover_peers(zeroconf, password)
            elif action == "6":
                stop_event.set()
                exit()
            elif action == "7":
                try:
                    print("Listening for requests. Press Ctrl+C to exit")
                    while not stop_event.is_set():
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("returning to main menu!")    
            elif action == "8":
                revoke_certificate(password)
            else:
                print("invalid input!\n")
        except KeyboardInterrupt:
                print("returning to main menu!")
        
if __name__ == "__main__":
    main()