from sender import *
from reciever import *

import os

def main():

    joinNetwork()
    print("Welcome to SecureShare V1.0. Please select an action to continue:\n"
          "\n"
          "1. View Available Files\n"
          "2. Send Request\n"
          "3. Quit\n")
    

    action = input("Enter action: ")

    if action == "1":
        print("one")
    if action == "2":
        print("two")
    if action == "3":
        exit()
    else:
        print("invalid input!\n")

if __name__ == "__main__":
    main()