from settings import *


class CA(KeyPair):
    def __init__(self):
        super().__init__()
        self.certificate = {
            "Version": 1,
            "Serial_Number": bytes(os.urandom(5)),
            "Subject_Name": "Root CA",
            "Public_Key_Algorithm": "Ed25519",
            "Public_Key_Bytes": self.key,
            "Signature_Algorithm": "Ed25519",
        }
        to_be_signed = json.dumps(self.certificate, sort_keys=True)
        to_be_signed_bytes = to_be_signed.encode("utf-8")
        signature = self.sign_certificate(to_be_signed_bytes)
        self.certificate['Signature'] = signature
        print(self.certificate)

    # For signing the server

    def sign(self, certificate):
        certificate_digest = hashlib.sha256(certificate)


ca = CA()
