from settings import *


class CA(KeyPair):
    def __init__(self):
        super().__init__()

        self.valid_before = datetime(1970, 1, 1)
        self.valid_after = datetime(2030, 12, 31)

        self.issuer = x509.Name([

            x509.NameAttribute(NameOID.COUNTRY_NAME, "TH"),

            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bangkok"),

            x509.NameAttribute(NameOID.LOCALITY_NAME, "Bangkok"),

            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ])

        subject = self.issuer

        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.issuer
        ).public_key(
            self.key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            self.valid_before
        ).not_valid_after(
            self.valid_after
        ).sign(self.get_priv(), algorithm=None)

    # CA creates the certificate for the server
    def sign_certificate(self, pub_key, subject):
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.issuer
        ).public_key(
            pub_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            self.valid_before
        ).not_valid_after(
            self.valid_after
        ).sign(self.get_priv(), algorithm=None)  # Sign by CA
        return certificate


root_ca = CA()
