import datetime
import ipaddress

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12, NoEncryption

from OpenSSL.crypto import *

from os import listdir
from os.path import isfile, join
from pathlib import Path

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


def get_crl_from_file(crl_file_path):
    crl_pem = read_file_bytes(crl_file_path)
    return pem2crl(crl_pem)

def save_crl(crl, file_path):
    save_certificate(crl, file_path)


def pem2crl(crl_pem):
    return x509.load_pem_x509_crl(data=crl_pem, backend=default_backend())


def gen_pkcs12(certs_chain_PATHS, key_path):
    # Generate a file that is ready to be written with "f=open(path, 'wb');f.write(data)"

    # TODO: check if we can do something for the PEM passphrase: "None"
    # serialized_pkcs12 = pkcs12.serialize_key_and_certificates(
    #     name=get_certificate_attribute_value(certs_chain_PATHS[0], NameOID.USER_ID),
    #     key=key_path,
    #     cert=certs_chain_PATHS[0],
    #     cas=certs_chain_PATHS[1:],
    #     encryption_algorithm=NoEncryption)
    # return serialized_pkcs12

    pkcs12 = PKCS12()

    with open(key_path, 'r') as key_file:
        key = load_privatekey(FILETYPE_PEM,key_file.read())
        pkcs12.set_privatekey(key)

    with open(certs_chain_PATHS[0], 'r') as cert_file:
        user_cert = load_certificate(FILETYPE_PEM, cert_file.read())
        pkcs12.set_certificate(user_cert)

    ca_certs=[]
    for ca_path in certs_chain_PATHS[1:]:
        with open(ca_path, 'r') as ca_file:
            ca_cert = load_certificate(FILETYPE_PEM, ca_file.read())
        ca_certs.append(ca_cert)

    pkcs12.set_ca_certificates(ca_certs)

    return pkcs12.export()



def get_cert_from_uid(uid):
    """
    Returns a certificate corresponding to the user id if there is some.
    None if none issued or already revoked
    """
    # Get all issued cert for a given uid
    folder_name = get_curr_intermediate_ca_user()
    folder_path = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + folder_name + '/'

    # Return None if the intermediate cert has been revoked
    crl_root = CRL()
    _, crl_pem = crl_root.get_crl()
    if is_revoked(get_cert_from_file(folder_path + folder_name + INTERMEDIATE_SUFFIX_CERT_NAME), crl_pem=crl_pem):
        return None

    issued_path = folder_path + ISSUED_FOLDER_NAME

    all_issued_certs_for_uid = [
        c for c in listdir(issued_path)
        if (isfile(join(issued_path, c)) and f.endswith('.pem') and (uid in c))
    ]

    # Get all cert that has been revoked from the previous set
    crl = CRL(folder_path=folder_path,
        cert_path=folder_path+folder_name+INTERMEDIATE_SUFFIX_CERT_NAME,
        private_key_path=ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + folder_name + INTERMEDIATE_SUFFIX_PRIVKEY_NAME)  # create a CRL to check if a cert has been revoked
    _, crl_pem = crl.get_crl()

    # Now mix the two results to extract the valid certs
    valid_certs = [
        c for c in all_issued_certs_for_uid
        if not is_revoked(get_cert_from_file(issued_path + c), crl_pem=crl_pem)
    ]

    # if there exists a valid certificate, returns it
    if len(valid_certs) > 0:
        cert = get_cert_from_file(issued_path + valid_certs[0])
        return cert

    # else, return None
    return None

def get_curr_intermediate_ca_user():
    with open(CURRENT_USER_INTERMEDIATE_NAME_FILE_PATH, 'r') as f:
        name = f.read()
    return name

def set_curr_intermediate_ca_user(name):
    with open(CURRENT_USER_INTERMEDIATE_NAME_FILE_PATH, 'w') as f:
        f.write(name)

def get_certificate_attribute_value(cert, oid):
    try:
        res = cert.subject.get_attributes_for_oid(oid)[0].value
        return res
    except:
        return None

def get_cert_and_key_names(cert):
    name = f"{get_certificate_attribute_value(cert, NameOID.USER_ID)}_{cert.serial_number}"
    return name+'.crt', name+'.pem'

def get_cert_and_key_path(cert):
    cert_issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    cert_name, key_name = get_cert_and_key_names(cert)

    if cert_issuer == ROOT_ORGANIZATION_NAME:
        cert_path = ROOT_FOLDER + ISSUED_FOLDER_NAME + cert_name
        key_path = ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + key_name
    else:
        extracted_issuer_name = cert_issuer[len(INTERMEDIATE_FOLDER_PREFIX):]
        issuer_folder = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + extracted_issuer_name + '/'
        cert_path = issuer_folder + ISSUED_FOLDER_NAME + cert_name
        key_path = issuer_folder + PRIVKEYS_FOLDER_NAME + key_name

    return cert_path, key_path


def verify_certificate(cert_path, inter_folder_path=None):
    # First, verify signatures
    root_cert = get_cert_from_file(ROOT_CERT_PATH)
    cert = get_cert_from_file(cert_path)
    #curr_inter_folder_name = get_curr_intermediate_ca_user() # TODO: restore this line and delete next one
    curr_inter_folder_name = 'TLS'
    signature_verified = False
   
    if inter_folder_path is not None:
        try:
            inter_cert = get_cert_from_file(inter_folder_path+curr_inter_folder_name+INTERMEDIATE_SUFFIX_CERT_NAME) 
            inter_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm)

            root_cert.public_key().verify(
                inter_cert.signature,
                inter_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                inter_cert.signature_hash_algorithm)

            signature_verified = True
        except InvalidSignature:
            return False
    else:
        try:
            root_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm)
            signature_verified=True
        except InvalidSignature:
            return False

    # Check that the certificate has been revoked
    revoked = True
    if inter_folder_path is not None:
        # Check if issued cert is revoked
        inter_cert_path = inter_folder_path+curr_inter_folder_name+INTERMEDIATE_SUFFIX_CERT_NAME
        crl = CRL(folder_path=inter_folder_path,
            cert_path=inter_cert_path,
            private_key_path=ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + curr_inter_folder_name + INTERMEDIATE_SUFFIX_PRIVKEY_NAME)
        _, crl_pem = crl.get_crl()
        cert_revoked = is_revoked(cert, crl_pem=crl_pem)

        # Check if inter is revoked
        crl = CRL(folder_path=ROOT_FOLDER,
            cert_path=ROOT_CERT_PATH,
            private_key_path=ROOT_PRIVKEY_PATH)
        _, crl_pem = crl.get_crl()
        inter_cert_revoked = is_revoked(get_cert_from_file(inter_cert_path), crl_pem=crl_pem)

        revoked = cert_revoked or inter_cert_revoked
    else:
        crl = CRL(folder_path=ROOT_FOLDER,
            cert_path=ROOT_CERT_PATH,
            private_key_path=ROOT_PRIVKEY_PATH)
        _, crl_pem = crl.get_crl()
        inter_cert_revoked = is_revoked(cert, crl_pem=crl_pem)

        revoked = False

    return signature_verified and (not revoked)

### Create certificates ############################################


def gen_root_ca():
    private_key = gen_private_key(4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'CH'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Zurich'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Zurich'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ROOT_ORGANIZATION_NAME),
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


def gen_intermediate_ca(name, root_cert, root_key, init_phase=False):
    # Create the intermediate folders in the root->issued folder
    inter_folder = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + name + '/'
    # Firstly, check if it exists and raise an exception if the folder already exists and we are not in the init_phase
    if Path(inter_folder).is_dir() and not init_phase:
        raise Exception('ERR: The intermediate certificate with name "' + name + '" already exists. Choose an other name.')

    folders_to_create = [inter_folder+ISSUED_FOLDER_NAME, inter_folder+REVOKED_FOLDER_NAME, inter_folder+PRIVKEYS_FOLDER_NAME]
    for need_to_exist in folders_to_create:
        Path(need_to_exist).mkdir(parents=True, exist_ok=True)

    private_key = gen_private_key(4096)

    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'CH'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Zurich'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Zurich'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, INTERMEDIATE_FOLDER_PREFIX + name),
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
    # TODO: get issuer folder with inter_crt.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    private_key = gen_private_key(2048)

    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'CH'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Zurich'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Zurich'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'iMovies'),
            x509.NameAttribute(NameOID.USER_ID, u'{}'.format(user_id)),
            x509.NameAttribute(NameOID.SURNAME, u'{}'.format(user_last_name)),
            x509.NameAttribute(NameOID.GIVEN_NAME,
                               u'{}'.format(user_first_name)),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS,
                               u'{}'.format(user_email)),
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
    # TODO: get issuer folder with inter_crt.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    private_key = gen_private_key(2048)

    certificate = x509.CertificateBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'CH'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Zurich'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'Zurich'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'iMovies'),
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

def revoke_cert(cert):
    builder = x509.RevokedCertificateBuilder()
    builder = builder.revocation_date(datetime.datetime.utcnow())
    builder = builder.serial_number(cert.serial_number)
    return builder.build(backend=default_backend())

def gen_revocation_list(revoked_folder_path):
    return [
        revoke_cert(get_cert_from_file(revoked_folder_path + p))
        for p in listdir(revoked_folder_path) if p.endswith('.pem')
    ]


class CRL:
    def __init__(self, folder_path=ROOT_FOLDER, cert_path=ROOT_CERT_PATH, private_key_path=ROOT_PRIVKEY_PATH):
        # Specify the parameters if it's different than root
        #super(CRL, self).__init__()
        self.folder_path = folder_path
        self.cert_path = cert_path
        self.private_key_path = private_key_path

        self.revoked_certificates = gen_revocation_list(self.folder_path +
                                                        REVOKED_FOLDER_NAME)

    def get_crl(self):
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

    def update_crl(self, cert_to_revoke):
        cert_name,_ = get_cert_and_key_names(cert_to_revoke)
        save_certificate(cert_to_revoke, self.folder_path + REVOKED_FOLDER_NAME + cert_name)
        self.revoked_certificates.append(revoke_cert(cert_to_revoke))
        crl, crl_pem = self.get_crl()
        save_crl(crl, self.folder_path + CRL_NAME)

        return crl, crl_pem

    # def get_revoked_certs_by_serial_number(self, serial_number):
    #     # Get revoked serial numbers
    #     revoked_serial_numbers = [rc.serial_number for rc in self.revoked_certificates]

    #     # Check if the param is in the list
    #     return (serial_number in revoked_serial_numbers)

def is_revoked(certificate, crl_pem=None, crl_path=''):
    if crl_pem:
        crl = pem2crl(crl_pem)
    else:
        crl = get_crl_from_file(crl_path)

    return crl.get_revoked_certificate_by_serial_number(certificate.serial_number)