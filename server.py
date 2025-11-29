from settings import *
from ca import root_ca
from client import *


class Server(KeyPair):
    def __init__(self, ca):
        super().__init__()
        self.subject = x509.Name([

            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),

            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example-server"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Nevada"),
        ])
        self.certificate = ca.sign_certificate(self.key, self.subject)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.transcript_hash = hashlib.sha256()

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((HOST, PORT))
        self.socket.listen()
        self.conn, addr = self.socket.accept()
        print(f"Accept Connection from {addr}")

        # Do the TLS flow then send the message
        return self.conn  # To be used later? If we do a different func

    def server_hello(self):
        self.server_private_ephiperal_key = X25519PrivateKey.generate()
        self.server_public_ephiperal_key = self.server_private_ephiperal_key.public_key()

    def communicate(self):
        # Do all the TLS stuff onwards here

        self.conn.close()


def main():
    server = Server(ca=root_ca)
    server.connect()
    server.communicate()


if __name__ == '__main__':
    main()
