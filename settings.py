import socket
import os
import hashlib
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = 'localhost'
PORT = 9914

# https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate


class KeyPair:
    def __init__(self):
        self.__private_key = Ed25519PrivateKey.generate()
        self.key = self.__private_key.public_key()

    def get_priv(self):
        return self.__private_key

    def save_keys(self, name, pub_path='certs', priv_path='private_certs'):
        with open(f'{priv_path}/{name}-key.pem', 'wb') as f:
            f.write(self.__private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(f'{pub_path}/{name}.pem', 'wb')as f:
            f.write(self.key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
