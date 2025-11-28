import socket
import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HOST = 'localhost'
PORT = 9914


class KeyPair:
    def __init__(self):
        self.__private_key = Ed25519PrivateKey.generate()
        self.key = self.__private_key.public_key()

    def sign_certificate(self, certificate):
        return self.__private_key.sign(certificate)


# keya = KeyPair()
# print(keya.key.public_bytes_raw())
