# 468-Final Project

## Overview
This project has two clients:
1. A **Python** client
2. A **JavaScript** client.

The clients largely obey the same design principles, so they should be able to communicate with each other.

---

## Python Client
### Description

### Setup
1. Ensure you have Python 3.8+ installed.
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the client:
    ```bash
    python main.py
    ```
---

## JavaScript Client
### Description


### Setup
1. Ensure you have Node.js (20+) installed.
2. Install dependencies:
    ```bash
    npm install
    ```
3. Start the development server:
    ```bash
    node .
    ```
---

### Usage
## JavaScript
The JavaScript application gives you the following options:
- connect
- list
- friends
- files
- request
- revoke_key
- decrypt
- exit

The `connect` option can be used to designate a peer as "trusted". Peers discovered over mDNS are shown in the console with their name everytime they're found.
The `list` option will show you all the peers discovered by mDNS (that meet the service type filter).
The `friend` option will show you all the peers that have been trusted by you, and display if they're online or not.
The `files` option allows you to request a file list from a peer. You will be asked to input the name of the peer.
The `request` option will let you request a specific file from a list. You will be asked to input the name of the peer to request from and the file you're looking for.
The `revoke_key` option will propagate a key revocation across the network and refresh your client's keypair.
The `decrypt` option will decrypt an encrypted file in your vault. After 30 seconds, the file will automatically be encrypted again.

**How to add a new file to the file vault?**
To add a new file, visit the configuration directory (`~/.p2p-agent`). On Windows, this is in `C:\Users\YOURUSERNAME\.p2p-agent`. In this directory, there should be a folder named `file_vault`.  
Simply add a file to this folder and it will be encrypted the next time you start the client, or within the next 30 seconds if the client is already open.

## Python
The Python client presents the following options:
- View Available Files
- Interact With A Peer
- Upload A File
- Export A File
- Add A Peer
- Quit
- Listen for Requests

The `View Available Files` option will list the file lists obtained from sending LIST_FILES requests to peers.
The `Interact With A Peer` option will ask the user to choose a trusted peer to connect with and then present the following options:
- LIST_FILES
- SEND_FILE
- REQUEST_FILE

`LIST_FILES` will obtain a list of files available to share by the peer.
`SEND_FILES` will prompt the user for the name of the file to send (must be uploaded to vthe ault) 
`REQUEST_FILE` will prompt the user to request the name of the file and receive it in the vault.

The `Upload A File` option will take the full path of a file on the system and copy the file to the vault, storing it in an encrypted state.
The `Export A File` option will decrypt a file from the vault and copy it outside the vault directory.
The `Add A Peer` option will search for peers, present the user with a list of peers to add, and ask the user to trust the peer.
The `Quit` option exits the program.
The `Listen for Requests` option allows the user to respond to requests without being interrupted from the main menu input.

## Login
To create a user, the password must be 12 characters long and contain the following:
- 1 uppercase letter
- 1 lowercase letter
- 1 number
- 1 special character
