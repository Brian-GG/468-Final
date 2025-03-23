import ssl
import socket
import json
import hashlib
import os


if os.path.exists("peers.json"):
    with open("peers.json", "r") as f:
        trusted_peers = json.load(f)
else: trusted_peers = {}

