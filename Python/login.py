import json
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password):
    return ph.hash(password)

def verify_password(stored_hash, password):
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    
def register_user(password):
    with open("user.json", "r") as f:
        users = json.load(f)

    users = hash_password(password)

    with open("user.json", "w") as f:
        json.dump(users, f, indent=4)

    print("User registered successfully!")
    return password

def login():
    with open("user.json", "r") as f:
        users = json.load(f)

    tries = 0
    while tries < 3:
        password = input("Enter Password: \n")

        if verify_password(users, password):
            print("Successfully Logged In!")
            return password
        else:
            print("Incorrect Password!")
            tries+=1
    if tries == 2:
        print("Too many failed password attmpts! Exiting...")
        time.sleep(1)
        exit()



    