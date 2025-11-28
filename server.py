from ca import *


class Server(KeyPair):
    def __init__(self, ca):
        super().__init__()
        self.subject = x509.Name([

            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),

            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),

            x509.NameAttribute(NameOID.LOCALITY_NAME, "Nevada"),
        ])
        self.certificate = ca.sign_certificate(self.key, self.subject)
