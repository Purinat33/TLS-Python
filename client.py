from settings import *
from ca import root_ca
from server import *


class Client(KeyPair):
    def __init__(self, ca):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.root_ca = ca

    def verify_server_cert(self, server_cert):
        # Use root_ca pub key to verify the cert
        pass

    def connect(self):
        self.socket.connect((HOST, PORT))

    def client_hello(self):
        self.client_random = os.urandom(32)  # 32 Bytes

    def communicate(self):
        # Do the communication here
        self.socket.send(self.client_random)


def main():
    client = Client(
        ca=root_ca
    )
    client.connect()
    client.client_hello()
    client.communicate()


if __name__ == '__main__':
    main()
