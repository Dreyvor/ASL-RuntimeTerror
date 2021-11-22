
import datetime
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

validity_root_days = 10*365
validity_intermediate_days = 5*365
validity_user_days = 365
validity_TLS_days = 365

CERTIFICATES_PATH = '/home/brad/MA04/Applied_security_laboratory/project/runtime_terror/src/ca-server/dreyvor/certs/'
KEYS_PATH = '/home/brad/MA04/Applied_security_laboratory/project/runtime_terror/src/ca-server/dreyvor/keys/'

### Utils ##########################################################

def gen_private_key(key_size):
    return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend())

def save_certificate(cert, filename):
    with open(CERTIFICATES_PATH + filename, 'w') as file:
        file.write(
            cert.public_bytes(encoding=serialization.Encoding.PEM).decode())

def save_key(key, filename):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEYS_PATH + filename, 'wb') as pem_out:
        pem_out.write(pem)

### Create certificates ############################################

def gen_root_ca():
    private_key = gen_private_key(4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMoviesRootCA"),
    ])

    root_certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_root_days)
    ).add_extension(
        x509.BasicConstraints(
            ca=True, path_length=1
        ), critical=True
    ).sign(private_key, hashes.SHA256(), default_backend())


    return root_certificate, private_key

    # certificate = root_certificate
    # return (certificate.public_bytes(serialization.Encoding.PEM),
    #     private_key.private_bytes(serialization.Encoding.PEM,
    #         serialization.PrivateFormat.PKCS8,
    #         serialization.NoEncryption()))

def gen_intermediate_cert(root_cert, root_key):
    private_key = gen_private_key(4096)

    certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMoviesIntermediateCA"),
    ])).issuer_name(
        root_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_intermediate_days)
    ).add_extension(
        x509.BasicConstraints(
            ca=True, path_length=0
        ), critical=True
    ).sign(root_key, hashes.SHA256(), default_backend())

    return certificate, private_key


def gen_user_ca(user_id, user_surname, user_given_name, user_email, issuer_cert, issuer_key):
    private_key = gen_private_key(2048)

    certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
        x509.NameAttribute(NameOID.USER_ID, u"{}".format(user_id)),
        x509.NameAttribute(NameOID.SURNAME, u"{}".format(user_last_name)),
        x509.NameAttribute(NameOID.GIVEN_NAME, u"{}".format(user_first_name)),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"{}".format(user_email)),
    ])).issuer_name(
        issuer_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_user_days)
    ).add_extension(
        x509.BasicConstraints(
            ca=False, path_length=None
        ), critical=True
    ).sign(issuer_key, hashes.SHA256(), default_backend())

    return certificate, private_key

def gen_TLS_ca(ip_addr, issuer_cert, issuer_key):
    private_key = gen_private_key(2048)

    certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
    ])).issuer_name(
        issuer_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_TLS_days)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.IPv4Address(ip_addr))
        ]), critical=False
    ).add_extension(
        x509.BasicConstraints(
            ca=False, path_length=None
        ), critical=True
    ).sign(issuer_key, hashes.SHA256(), default_backend())

    return certificate, private_key




### MAIN ########################################################

def main():
    root_cert, root_key = gen_root_ca()
    save_certificate(root_cert, 'root.crt')
    save_key(root_key, 'root.pem')
    
    inter_cert, inter_key = gen_intermediate_cert(root_cert, root_key)
    save_certificate(inter_cert, 'inter.crt')
    save_key(inter_key, 'inter.pem')

    TLS_srv_cert, TLS_srv_key = gen_TLS_ca('127.0.0.1', inter_cert, inter_key)
    save_certificate(TLS_srv_cert, 'TLS_srv.crt')
    save_key(TLS_srv_key, 'TLS_srv.pem')

    TLS_cli_cert, TLS_cli_key = gen_TLS_ca('127.0.0.1', inter_cert, inter_key)
    save_certificate(TLS_cli_cert, 'TLS_cli.crt')
    save_key(TLS_cli_key, 'TLS_cli.pem')

if __name__ == '__main__':
    main()