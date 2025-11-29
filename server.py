from settings import *
from ca import *
from client import *


class Server(KeyPair):
    def __init__(self, ca: CA):
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

        # Internal buffer to get input
        self.file_obj = self.conn.makefile('rb')

        # Do the TLS flow then send the message
        return self.conn  # To be used later? If we do a different func

    def server_hello(self):
        self.server_private_ephiperal_key = X25519PrivateKey.generate()
        self.server_public_ephiperal_key = self.server_private_ephiperal_key.public_key()
        self.server_random = os.urandom(32).hex()  # 32 Bytes

        eph_public_key_bytes = self.server_public_ephiperal_key.public_bytes_raw().hex()

        self.protocol_version = 1
        self.cipher_suits = 'X25519'
        self.server_name = 'example-server'

        self.server_hello_msg = json.dumps({
            "ServerRandom": self.server_random,
            "Version": self.protocol_version,
            "EphPubKey": eph_public_key_bytes,
            "Suite": self.cipher_suits,
        })
        self.server_hello_msg += '\n'
        self.server_hello_msg = self.server_hello_msg.encode()

    def communicate(self):
        # Do all the TLS stuff onwards here

        # 1.
        # Receive Client Hello +
        self.client_hello = self.file_obj.readline()
        # Update hash
        self.transcript_hash.update(self.client_hello)

        # 2.
        # Server Hello
        self.server_hello()
        self.conn.send(self.server_hello_msg)
        self.transcript_hash.update(self.server_hello_msg)

        # 3.
        # Decode hello message
        original_hello_msg = json.loads(self.client_hello)
        self.client_random = original_hello_msg['ClientRandom']
        client_eph_pub = original_hello_msg['EphPubKey']
        self.server_name = original_hello_msg['ServerName']
        # Perform checking stuff (Optional)
        if self.server_name != self.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
            print("Wrong Server Name")
            self.conn.close()
        print("Server Correct")

        self.client_eph_pub = X25519PublicKey.from_public_bytes(
            bytes.fromhex(client_eph_pub))

        # print(self.client_eph_pub.public_bytes_raw().hex())
        # print(self.server_public_ephiperal_key.public_bytes_raw().hex())

        # 4. Compute Shared Secret
        self.shared_secret = self.server_private_ephiperal_key.exchange(
            self.client_eph_pub)
        # print(self.shared_secrets.hex())

        # 5. Derived HKDF from shared secrets
        self.derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Handshake Data'
        ).derive(self.shared_secret)

        # print(self.derived_key.hex())

        # 6. Send Certificate
        cert_to_send = json.dumps(
            self.certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ).hex()
        ).encode()

        self.transcript_hash.update(cert_to_send)
        self.conn.send(cert_to_send)
        # print(self.transcript_hash.hexdigest())
        # print(self.certificate.public_key())

        # Final Step
        self.conn.close()

    # https://realpython.com/ref/stdlib/hashlib/
    def compare_hash(self, client_hash):
        # Compare transcript hash, if it's not equal then send out a text and close connection
        self_sha256 = self.transcript_hash.hexdigest()
        client_sha256 = client_hash.hexdigest()

        if self_sha256 != client_sha256:
            self.conn.send(b"SHA Broken")
            self.conn.close()


def main():
    server = Server(
        ca=root_ca
    )
    server.connect()
    server.communicate()


if __name__ == '__main__':
    main()
