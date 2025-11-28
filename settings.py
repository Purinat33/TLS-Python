import socket
import os
import hashlib
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID


HOST = 'localhost'
PORT = 9914

# https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate


class KeyPair:
    def __init__(self):
        self.__private_key = Ed25519PrivateKey.generate()
        self.key = self.__private_key.public_key()

    def get_priv(self):
        return self.__private_key
