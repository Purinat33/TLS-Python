from settings import *
from ca import root_ca
from server import *


class Client(KeyPair):
    def __init__(self, ca):
        super().__init__()
        self.root_ca = ca

    def verify_server_cert(self, server_cert):
        # Use root_ca pub key to verify the cert
        pass

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))

        data = self.socket.recv(1024)
        print(data.decode())


def main():
    client = Client(
        ca=root_ca
    )
    client.connect()


if __name__ == '__main__':
    main()
