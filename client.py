from settings import *
from ca import *
from server import *


class Client(KeyPair):
    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.root_ca = root_ca
        self.transcript_hash = hashlib.sha256()

    def verify_server_cert(self, server_cert: x509.Certificate):
        # Use root_ca pub key to verify the cert
        if server_cert.issuer != self.root_ca.issuer:
            print("Incorrect Issuer")
        else:
            print("Correct CA")

        signature = server_cert.signature
        tbs_cert = server_cert.tbs_certificate_bytes
        self.root_ca.key.verify(signature, tbs_cert)

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

        # 4. Compute Shared Secret
        self.shared_secret = self.client_ephemeral_private_key.exchange(
            self.server_eph_pub)
        # print(self.shared_secret.hex())

        # 5. Derived HKDF from shared secrets
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Handshake Data'
        ).derive(self.shared_secret)

        # print(self.derived_key.hex())

        # 6. Receive Certificate
        serv_certificate = self.file_obj.readline()
        self.transcript_hash.update(serv_certificate)
        # print(self.transcript_hash.hexdigest()) # Both side matches
        server_certificate_pem = bytes.fromhex(
            json.loads(serv_certificate.decode()))

        self.server_certificate = x509.load_pem_x509_certificate(
            server_certificate_pem)

        # 7. Client verify server cerificate using CA public key
        # print(self.server_certificate)
        self.verify_server_cert(self.server_certificate)


def main():
    client = Client()
    client.connect()
    client.communicate()


if __name__ == '__main__':
    main()
