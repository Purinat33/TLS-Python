from settings import *
from client import *


class Server:
    def __init__(self):
        # Load Certificate
        cert_path = 'certs/server_certificate.pem'
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            self.certificate = x509.load_pem_x509_certificate(cert_data)

        except FileNotFoundError:
            print(f"Error: certificate file not found at {cert_path}")

        except ValueError as e:
            print(f"Error loading certificate: {e}")

        # Load Private Key
        priv_path = 'private_certs/server-key.pem'
        try:
            with open(priv_path, 'rb') as f:
                priv_data = f.read()
            self._private_key = serialization.load_pem_private_key(
                priv_data, password=None)

        except FileNotFoundError:
            print(f"Error: private key file not found at {priv_path}")

        except ValueError as e:
            print(f"Error loading private key: {e}")

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
        # if self.server_name != self.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
        #     print("Wrong Server Name")
        #     self.conn.close()
        # print("Server Correct")

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
        )
        cert_to_send += '\n'
        cert_to_send = cert_to_send.encode()

        self.transcript_hash.update(cert_to_send)
        self.conn.send(cert_to_send)
        # print(self.transcript_hash.hexdigest())
        # print(self.certificate.public_key())

        # 7. Certificate Verify
        hash_for_sig = self.transcript_hash.copy().digest()
        self.signed_digest = self._private_key.sign(hash_for_sig)

        # Send the Certificate Verify message
        self.certificate_verify_handshake = json.dumps(
            self.signed_digest.hex()
        )
        self.certificate_verify_handshake += '\n'
        self.certificate_verify_handshake = self.certificate_verify_handshake.encode()

        self.transcript_hash.update(self.certificate_verify_handshake)
        self.conn.send(self.certificate_verify_handshake)

        print(self.transcript_hash.hexdigest())

        # 8. Finished Message Server
        self.finished_key_server = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"server finished"
        ).derive(self.derived_key)

        self.finished_key_client = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"client finished"
        ).derive(self.derived_key)

        finished_hash = self.transcript_hash.copy().digest()
        h = hmac.HMAC(self.finished_key_server, hashes.SHA256())
        h.update(finished_hash)
        server_finished_mac = h.finalize()

        # Send finished message to the Client
        self.server_finished_handshake = json.dumps(
            server_finished_mac.hex()
        )
        self.server_finished_handshake += '\n'
        self.server_finished_handshake = self.server_finished_handshake.encode()

        self.transcript_hash.update(self.server_finished_handshake)
        self.conn.send(self.server_finished_handshake)

        # print(server_finished_mac.hex())

        # 9. Finished Message Client
        client_finished = self.file_obj.readline()
        to_verify = self.transcript_hash.copy().digest()
        self.transcript_hash.update(client_finished)

        self.client_mac = bytes.fromhex(
            json.loads(client_finished.decode())
        )

        h = hmac.HMAC(self.finished_key_client, hashes.SHA256())
        h.update(to_verify)
        h.verify(self.client_mac)

        print()
        print(self.client_mac.hex())
        print()
        print(self.server_finished_handshake.hex())
        
        
        # 10. Write Key
        self.client_app_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"client app key"
        ).derive(self.derived_key)

        self.client_app_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=None,
            info=b"client app iv"
        ).derive(self.derived_key)

        self.server_app_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"server app key"
        ).derive(self.derived_key)

        self.server_app_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=None,
            info=b"server app iv"
        ).derive(self.derived_key)

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
    server = Server()
    server.connect()
    server.communicate()


if __name__ == '__main__':
    main()
