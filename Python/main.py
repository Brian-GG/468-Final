from sender import *
from reciever import *
from filemanager import *
from login import *

import os

def main():


    password = create_user_file()
    password = login()
    joinNetwork()
    print("Welcome to SecureShare V1.0. Please select an action to continue:\n"
          "\n"
          "1. View Available Files\n"
          "2. Request A File\n"
          "3. Send A File\n"
          "4. Upload A File\n"
          "5. Quit\n")
    

    action = input("Enter action: ")

    if action == "1":
        print("one")
    if action == "2":
        print("two")
    if action == "3":
        print("two")
    if action == "4":
        import_files(password)
    if action == "5":
        exit()
    else:
        print("invalid input!\n")

if __name__ == "__main__":
    main()