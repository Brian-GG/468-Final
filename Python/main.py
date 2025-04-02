from sender import *
from reciever import *
from filemanager import *
from login import *

import os

def main():


    password = create_user_file()
    password = login()
    joinNetwork()
    create_data_files()
    generate_uid()
    while True:
        
        print("Welcome to SecureShare V1.0. Please select an action to continue:\n"
            "\n"
            "1. View Available Files\n"
            "2. Request A File\n"
            "3. Send A File\n"
            "4. Upload A File\n"
            "5. Export A File\n"
            "6. Add A Peer\n"
            "7. Quit\n")
        

        action = input("Enter action: ")

        if action == "1":
            print("one")
        elif action == "2":
            print("two")
        elif action == "3":
            print("two")
        elif action == "4":
            import_files(password)
        elif action == "5":
            export_file(password)
        elif action == "6":
            exit()
        elif action == "7":
            exit()
        else:
            print("invalid input!\n")

if __name__ == "__main__":
    main()