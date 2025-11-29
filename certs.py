from settings import *

from ca import *


def main():
    root_ca = CA()
    root_ca.save_keys("root_ca")
    root_ca.save_cerificate()

    # Move Server creation here
    server_keys = KeyPair()
    server_keys.save_keys("server")

    server_subject = x509.Name([

        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),

        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example-server"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Nevada"),
    ])
    server_certificate = root_ca.sign_certificate(
        server_keys.key, server_subject)
    with open(f"certs/server_certificate.pem", "wb") as f:
        f.write(server_certificate.public_bytes(serialization.Encoding.PEM))


if __name__ == '__main__':
    main()
