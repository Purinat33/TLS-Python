from settings import *
from server import *


class Client(KeyPair):
    def __init__(self):
        super().__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.transcript_hash = hashlib.sha256()

        # Load Root CA Certificate
        root_ca_path = 'certs/root_ca_certificate.pem'
        try:
            with open(root_ca_path, 'rb') as f:
                cert_data = f.read()
            self.root_ca = x509.load_pem_x509_certificate(cert_data)

        except FileNotFoundError:
            print(f"Error: certificate file not found at {root_ca_path}")

        except ValueError as e:
            print(f"Error loading certificate: {e}")

    def ca_verify_cert(self):
        if self.server_certificate.issuer != self.root_ca.subject:
            print("Invalid Certificate")

        # More verification (Date etc) if needed
        self.root_ca.public_key().verify(self.server_certificate.signature,
                                         self.server_certificate.tbs_certificate_bytes)
        print("Certificate Verification Passed")

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
        self.ca_verify_cert()

        # 8. Receive Certificate Verify data
        certificate_verify = self.file_obj.readline()
        hash_to_verify = self.transcript_hash.copy().digest()
        self.transcript_hash.update(certificate_verify)

        self.cv_signature = bytes.fromhex(
            json.loads(certificate_verify.decode())
        )

        self.server_certificate.public_key().verify(self.cv_signature, hash_to_verify)
        print(self.transcript_hash.hexdigest())

        # 9. Finished Message (Server)
        self.finished_key_client = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"client finished"
        ).derive(self.derived_key)

        self.finished_key_server = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"server finished"
        ).derive(self.derived_key)

        # Receive Finish Message (Server)
        server_finished = self.file_obj.readline()
        to_verify = self.transcript_hash.copy().digest()
        self.transcript_hash.update(server_finished)

        # Received MAC Server
        self.server_mac = bytes.fromhex(
            json.loads(server_finished.decode())
        )

        h = hmac.HMAC(self.finished_key_server, hashes.SHA256())
        h.update(to_verify)
        h.verify(self.server_mac)
        # print(self.server_mac.hex())

        # 10. Finished Message (Client)
        finished_hash = self.transcript_hash.copy().digest()
        h = hmac.HMAC(self.finished_key_client, hashes.SHA256())
        h.update(finished_hash)
        client_finished_mac = h.finalize()

        self.client_finished_handshake = json.dumps(
            client_finished_mac.hex()
        )

        self.client_finished_handshake += '\n'
        self.client_finished_handshake = self.client_finished_handshake.encode()

        self.transcript_hash.update(self.client_finished_handshake)
        self.socket.send(self.client_finished_handshake)

        print()
        print(self.server_mac.hex())
        print()
        print(self.client_finished_handshake.hex())


def main():
    client = Client()
    client.connect()
    client.communicate()


if __name__ == '__main__':
    main()
