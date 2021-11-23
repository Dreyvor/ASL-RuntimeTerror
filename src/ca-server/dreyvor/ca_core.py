import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from OpenSSL.crypto import *

from os import listdir
from os.path import isfile, join

# My files
from ca_config import *

### Utils ##########################################################


def gen_private_key(key_size):
    return rsa.generate_private_key(public_exponent=65537,
                                    key_size=key_size,
                                    backend=default_backend())


def read_file_bytes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return data


def get_cert_from_file(cert_file_path):
    cert_pem = read_file_bytes(cert_file_path)
    return x509.load_pem_x509_certificate(cert_pem, default_backend())


def get_key_from_file(key_file_path):
    key_pem = read_file_bytes(key_file_path)
    private_key = load_pem_private_key(key_pem, None, default_backend())
    return private_key


def save_certificate(cert, file_path):
    with open(file_path, 'w') as file:
        file.write(
            cert.public_bytes(encoding=serialization.Encoding.PEM).decode())


def save_key(key, file_path):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    with open(file_path, 'wb') as pem_out:
        pem_out.write(pem)


def gen_pkcs12_format_bytes(cert_path, key_path):
    # Generate a file that is ready to be written with "f=open(path, 'wb');f.write(data)"
    pkcs12 = PKCS12()

    with open(cert_path, "r") as cert_file:
        cert = load_certificate(FILETYPE_PEM, cert_file.read())
        pkcs12.set_certificate(cert)

    with open(key_path, "r") as key_file:
        key = load_privatekey(FILETYPE_PEM, key_file.read())
        pkcs12.set_privatekey(key)

    return pkcs12.export()


def get_cert_from_uid(uid):
    """
    Returns a certificate corresponding to the user id if there is some.
    None if none issued or already revoked
    """
    # Get all issued cert for a given uid
    all_issued_certs_for_uid = [
        c for c in listdir(ISSUED_PATH)
        if (isfile(join(ISSUED_PATH, c)) and f.endswith('.pem') and (uid in c))
    ]

    # Get all cert that has been revoked from the previous set
    crl = CRL()  # create a CRL to check if a cert has been revoked
    _, crl_pem = crl.get_crl()

    # Now mix the two results to extract the valid certs
    valid_certs = [
        c for c in all_issued_certs_for_uid
        if not is_revoked(get_cert_from_file(ISSUED_PATH + c), crl_pem=crl_pem)
    ]

    # if there exists a valid certificate, returns it
    if len(valid_certs) > 0:
        cert = get_cert_from_file(ISSUED_PATH + valid_certs[0])
        return cert

    # else, return None
    return None


### Create certificates ############################################


def gen_root_ca():
    private_key = gen_private_key(4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMoviesRootCA"),
    ])

    root_certificate = x509.CertificateBuilder(
    ).subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()).serial_number(
            x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()).not_valid_after(
                    datetime.datetime.utcnow() +
                    datetime.timedelta(days=validity_root_days)).add_extension(
                        x509.BasicConstraints(ca=True, path_length=1),
                        critical=True).sign(private_key, hashes.SHA256(),
                                            default_backend())

    return root_certificate, private_key

    # certificate = root_certificate
    # return (certificate.public_bytes(serialization.Encoding.PEM),
    #     private_key.private_bytes(serialization.Encoding.PEM,
    #         serialization.PrivateFormat.PKCS8,
    #         serialization.NoEncryption()))


def gen_intermediate_ca(root_cert, root_key):
    private_key = gen_private_key(4096)

    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               u"iMoviesIntermediateCA"),
        ])).issuer_name(root_cert.subject).public_key(
            private_key.public_key()).serial_number(
                x509.random_serial_number()).not_valid_before(
                    datetime.datetime.utcnow()).not_valid_after(
                        datetime.datetime.utcnow() + datetime.timedelta(
                            days=validity_intermediate_days)).add_extension(
                                x509.BasicConstraints(ca=True, path_length=0),
                                critical=True).sign(root_key, hashes.SHA256(),
                                                    default_backend())

    return certificate, private_key


def gen_user_cert(user_id, user_surname, user_given_name, user_email,
                  issuer_cert, issuer_key):
    private_key = gen_private_key(2048)

    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
            x509.NameAttribute(NameOID.USER_ID, u"{}".format(user_id)),
            x509.NameAttribute(NameOID.SURNAME, u"{}".format(user_last_name)),
            x509.NameAttribute(NameOID.GIVEN_NAME,
                               u"{}".format(user_first_name)),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS,
                               u"{}".format(user_email)),
        ])).issuer_name(issuer_cert.subject).public_key(
            private_key.public_key()).serial_number(
                x509.random_serial_number()).not_valid_before(
                    datetime.datetime.utcnow()).not_valid_after(
                        datetime.datetime.utcnow() + datetime.timedelta(
                            days=validity_user_days)).add_extension(
                                x509.BasicConstraints(ca=False,
                                                      path_length=None),
                                critical=True).sign(issuer_key,
                                                    hashes.SHA256(),
                                                    default_backend())

    return certificate, private_key


def gen_TLS_cert(ip_addr, issuer_cert, issuer_key):
    private_key = gen_private_key(2048)

    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
        ])).issuer_name(issuer_cert.subject).public_key(
            private_key.public_key()).serial_number(
                x509.random_serial_number()).not_valid_before(
                    datetime.datetime.utcnow()).not_valid_after(
                        datetime.datetime.utcnow() + datetime.timedelta(
                            days=validity_TLS_days)).add_extension(
                                x509.SubjectAlternativeName([
                                    x509.IPAddress(
                                        ipaddress.IPv4Address(ip_addr))
                                ]),
                                critical=False).add_extension(
                                    x509.BasicConstraints(ca=False,
                                                          path_length=None),
                                    critical=True).sign(
                                        issuer_key, hashes.SHA256(),
                                        default_backend())

    return certificate, private_key


### CRL #######################################################


def gen_revocation_list(revoked_folder_path):
    return [
        revoke_cert(get_cert_from_file(revoked_folder_path + p))
        for p in listdir(revoked_folder_path) if p.endswith('.pem')
    ]


class CRL:
    def __init__(self, folder_path, cert_path, private_key_path):
        #super(CRL, self).__init__()
        self.folder_path = folder_path
        self.cert_path = cert_path
        self.private_key_path = private_key_path

        self.revoked_certificates = gen_revocation_list(self.folder_path +
                                                        REVOKED_FOLDER_NAME)

    def get_crl():
        the_cert = get_cert_from_file(self.cert_path)
        the_key = get_key_from_file(self.private_key_path)

        CRL_builder = x509.CertificateRevocationListBuilder().last_update(
            datetime.datetime.utcnow()).next_update(
                datetime.datetime.utcnow() +
                datetime.timedelta(1, 0, 0)).issuer_name(the_cert.subject)

        # TODO: check if the intermediate cert is not revoked by root
        if self.revoked_certificates:
            for revoked_cert in self.revoked_certificates:
                CRL_builder.add_revoked_certificate(revoked_cert)

        crl = CRL_builder.sign(private_key=the_key,
                               algorithm=hashes.SHA256(),
                               backend=default_backend())

        return crl, crl.public_bytes(encoding=serialization.Encoding.PEM)

    def update_crl():
        return NotImplementedError


def is_revoked(certificate, crl_pem=None, crl_path=''):
    return NotImplementedError


### MAIN ########################################################


def main():
    root_cert, root_key = gen_root_ca()
    save_certificate(root_cert, ROOT_CERT_PATH)
    save_key(root_key, ROOT_PRIVKEY_PATH)

    inter_cert, inter_key = gen_intermediate_ca(root_cert, root_key)
    save_certificate(inter_cert, INTERMEDIATE_CERT_PATH)
    save_key(inter_key, INTERMEDIATE_PRIVKEY_PATH)

    TLS_srv_cert, TLS_srv_key = gen_TLS_cert('127.0.0.1', inter_cert,
                                             inter_key)
    save_certificate(TLS_srv_cert, ISSUED_PATH + 'TLS_srv.crt')
    save_key(TLS_srv_key, 'TLS_srv.pem')

    TLS_cli_cert, TLS_cli_key = gen_TLS_cert('127.0.0.1', inter_cert,
                                             inter_key)
    save_certificate(TLS_cli_cert, ISSUED_PATH + 'TLS_cli.crt')
    save_key(TLS_cli_key, PRIVKEYS_PATH + 'TLS_cli.pem')


if __name__ == '__main__':
    main()
