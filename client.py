from settings import *
from ca import root_ca
from server import *


class Client(KeyPair):
    def __init__(self, ca):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.root_ca = ca
        self.transcript_hash = hashlib.sha256()

    def verify_server_cert(self, server_cert):
        # Use root_ca pub key to verify the cert
        pass

    def connect(self):
        self.socket.connect((HOST, PORT))
        self.file_obj = self.socket.makefile('rb')

    def client_hello(self):
        self.client_random = os.urandom(32).hex()  # 32 Bytes
        self.client_ephemeral_private_key = X25519PrivateKey.generate()
        self.client_ephemeral_public_key = self.client_ephemeral_private_key.public_key()
        eph_public_key_bytes = self.client_ephemeral_public_key.public_bytes_raw().hex()

        self.protocol_version = 1
        self.cipher_suits = 'X25519'
        self.server_name = 'example-server'

        self.client_hello_msg = json.dumps({
            "ClientRandom": self.client_random,
            "Version": self.protocol_version,
            "EphPubKey": eph_public_key_bytes,
            "Suite": self.cipher_suits,
            "ServerName": self.server_name,
        })
        self.client_hello_msg += '\n'
        self.client_hello_msg = self.client_hello_msg.encode()

    def communicate(self):
        # Do the communication here

        # 1.
        # send + update transcript hash
        # Update after adding the new line
        self.client_hello()
        self.socket.send(self.client_hello_msg)
        self.transcript_hash.update(self.client_hello_msg)

        # 2.
        # Receive the server's Hello
        self.server_hello = self.file_obj.readline()
        self.transcript_hash.update(self.server_hello)

        # 3.
        # Decode hello message
        original_hello_msg = json.loads(self.server_hello)
        self.server_random = original_hello_msg['ServerRandom']
        server_eph_pub = original_hello_msg['EphPubKey']
        self.server_eph_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(server_eph_pub)
        )

        # print(self.server_eph_pub.public_bytes_raw().hex())
        # print(self.client_ephemeral_public_key.public_bytes_raw().hex())

def main():
    client = Client(
        ca=root_ca
    )
    client.connect()
    client.communicate()


if __name__ == '__main__':
    main()
