from settings import *


class CA(KeyPair):
    def __init__(self):
        super().__init__()

    # For signing the server
    def sign(self, certificate):
        # TBA
        certificate_digest = hashlib.sha256(certificate)


ca = CA()
