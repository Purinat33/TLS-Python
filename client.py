from settings import *
from ca import root_ca
from server import *


class Client(KeyPair):
    def __init__(self, ca):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.root_ca = ca
        self.transcript_hash = ""

    def verify_server_cert(self, server_cert):
        # Use root_ca pub key to verify the cert
        pass

    def connect(self):
        self.socket.connect((HOST, PORT))

    def client_hello(self):
        self.client_random = os.urandom(32)  # 32 Bytes
        self.client_ephemeral_private_key = X25519PrivateKey.generate()
        self.client_ephemeral_public_key = self.client_ephemeral_private_key.public_key()
        self.protocol_version = 1
        self.cipher_suits = 'X25519'
        self.server_name = 'example-server'

        self.client_hello_msg = bytes({
            "ClientRandom": self.client_random,
            "Version": self.protocol_version,
            "EphPubKey": self.client_ephemeral_public_key,
            "Suite": self.cipher_suits,
            "ServerName": self.server_name
        })

    def communicate(self):
        # Do the communication here
        self.client_hello()
        self.socket.send(self.client_hello_msg)


def main():
    client = Client(
        ca=root_ca
    )
    client.connect()
    client.communicate()


if __name__ == '__main__':
    main()
