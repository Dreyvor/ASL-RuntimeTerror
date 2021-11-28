import ssl
import logging
import time
import base64 as b64


from os import remove
from pathlib import Path
from threading import Thread, Lock
from flask import Flask, request, send_from_directory
from  OpenSSL import crypto


# My files
from ca_core import *
from ca_config import *


### MISC #################################################

lock = Lock()


### FUNCTIONS ############################################


def create_ssl_context():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    chain_cert_path = INTERMEDIATE_TLS_FOLDER + ISSUED_FOLDER_NAME + TLS_CA_SRV_NAME + SUFFIX_CERT_CHAIN_NAME
    key_path = INTERMEDIATE_TLS_FOLDER + PRIVKEYS_FOLDER_NAME + TLS_CA_SRV_NAME + '.pem'
    ssl_ctx.load_cert_chain(chain_cert_path, key_path)
    ssl_ctx.load_verify_locations(ROOT_CERT_PATH)
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ssl_ctx


def init_ca_server(logger):
    # Create paths if not done
    for need_to_exist in FOLDERS_THAT_NEED_TO_EXISTS:
        Path(need_to_exist).mkdir(parents=True, exist_ok=True)

    # if root certificate not present, then create new root and new intermediate certificates
    # ROOT
    root_already_existant = False
    try:
        root_cert = get_cert_from_file(ROOT_CERT_PATH)
        root_key = get_key_from_file(ROOT_PRIVKEY_PATH)
        root_already_existant = True
    except Exception as e:
        logger.info(
            '!!! WARNING !!!\nROOT CERTIFICATE NON-EXISTENT, WE CREATE A NEW ONE'
            + ' ' + str(e))
        root_cert, root_key = gen_root_ca()
        save_certificate(root_cert, ROOT_CERT_PATH)
        save_key(root_key, ROOT_PRIVKEY_PATH)

    # INTERMEDIATE_TLS
    inter_TLS_already_existant = False
    if root_already_existant:
        try:
            inter_TLS_cert = get_cert_from_file(INTERMEDIATE_TLS_CERT_PATH)
            inter_TLS_key = get_key_from_file(INTERMEDIATE_TLS_PRIVKEY_PATH)
            inter_TLS_already_existant = True
        except Exception as e:
            logger.info(
                '!!! WARNING !!!\nINTERMEDIATE TLS CERTIFICATE NON-EXISTENT, WE CREATE A NEW ONE'
                + ' ' + str(e))
            inter_TLS_cert, inter_TLS_key = gen_intermediate_ca(TLS_FOLDER_NAME, root_cert, root_key, init_phase=True)
            save_certificate(inter_TLS_cert, INTERMEDIATE_TLS_CERT_PATH)
            save_key(inter_TLS_key, INTERMEDIATE_TLS_PRIVKEY_PATH)
    else:
        logger.info(
            '!!! WARNING !!!\nINTERMEDIATE TLS CERTIFICATE EXISTS WITH AN OLD ROOT, WE CREATE A NEW ONE'
        )
        inter_TLS_cert, inter_TLS_key = gen_intermediate_ca(TLS_FOLDER_NAME, root_cert, root_key, init_phase=True)
        save_certificate(inter_TLS_cert, INTERMEDIATE_TLS_CERT_PATH)
        save_key(inter_TLS_key, INTERMEDIATE_TLS_PRIVKEY_PATH)

    # INTERMEDIATE_USER
    inter_user_already_existant = False
    curr_inter_user_name = get_curr_intermediate_ca_user()
    curr_inter_user_folder = get_curr_intermediate_ca_user_folder_path()
    curr_inter_user_cert_path = curr_inter_user_folder + curr_inter_user_name + INTERMEDIATE_SUFFIX_CERT_NAME
    curr_inter_user_key_path = ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + curr_inter_user_name + INTERMEDIATE_SUFFIX_PRIVKEY_NAME
    if root_already_existant:
        try:
            inter_user_cert = get_cert_from_file(curr_inter_user_cert_path)
            inter_user_key = get_key_from_file(curr_inter_user_key_path)
            inter_user_already_existant = True
        except Exception as e:
            logger.info(
                '!!! WARNING !!!\nINTERMEDIATE USER CERTIFICATE NON-EXISTENT, WE CREATE A NEW ONE'
                + ' ' + str(e))
            inter_user_cert, inter_user_key = gen_intermediate_ca(curr_inter_user_name, root_cert, root_key, init_phase=True)
            save_certificate(inter_user_cert, curr_inter_user_cert_path)
            save_key(inter_user_key, curr_inter_user_key_path)
            # Write current user intermediate name
            set_curr_intermediate_ca_user(curr_inter_user_name)
    else:
        logger.info(
            '!!! WARNING !!!\nINTERMEDIATE TLS CERTIFICATE EXISTS WITH AN OLD ROOT, WE CREATE A NEW ONE'
        )
        inter_user_cert, inter_user_key = gen_intermediate_ca(curr_inter_user_name, root_cert, root_key, init_phase=True)
        save_certificate(inter_user_cert, curr_inter_user_cert_path)
        save_key(inter_user_key, curr_inter_user_key_path)
        
        # Write current user intermediate name
        set_curr_intermediate_ca_user(curr_inter_user_name)


    # For each server generate a TLS certificate if not already created
    for srv_name, srv_ip in TLS_CERTS_NEEDED:
        cert_path = INTERMEDIATE_TLS_FOLDER + ISSUED_FOLDER_NAME + srv_name + '.crt'
        key_path = INTERMEDIATE_TLS_FOLDER + PRIVKEYS_FOLDER_NAME + srv_name + '.pem'
        if not (inter_user_already_existant and Path(cert_path).is_file()
                and not Path(cert_path).is_symlink()
                and Path(key_path).is_file()
                and not Path(key_path).is_symlink()):
            logger.info(
                '!!! WARNING !!!\nTLS CERTIFICATE NON-EXISTENT OR SIGNED WITH AN OLD INTERMEDIATE, WE CREATE A NEW ONE'
            )
            TLS_cert, TLS_key = gen_TLS_cert(srv_ip, srv_name, inter_TLS_cert, inter_TLS_key)
            save_certificate(TLS_cert, cert_path)
            save_key(TLS_key, key_path)

        # Generate TLS certificate chain to verify identity
        file_paths_for_CA_chain = [cert_path, INTERMEDIATE_TLS_CERT_PATH, ROOT_CERT_PATH]
        output_path = INTERMEDIATE_TLS_FOLDER + ISSUED_FOLDER_NAME + srv_name + SUFFIX_CERT_CHAIN_NAME
        gen_ca_chain_and_save(file_paths_for_CA_chain, output_path)

    # Generate the admin certificate that will have admin access to the web server, if not created
    if get_cert_from_uid('admin') is None:
        admin_cert, admin_priv_key = gen_user_cert('admin', 'Admynis', 'Traitor', 'admin@webserver.com', inter_user_cert, inter_user_key)
        cert_path, key_path = get_cert_and_key_path(admin_cert)
        save_certificate(admin_cert, cert_path)
        save_key(admin_priv_key, key_path)
        pkcs12_admin = gen_pkcs12([cert_path, curr_inter_user_cert_path, ROOT_CERT_PATH], key_path)
        with open('/home/ca-server/admin.p12', 'wb') as f:
            f.write(pkcs12_admin)

    # Create the stats files if they don't exist
    stat_paths = [ISSUED_COUNTER, REVOKED_COUNTER, SERIAL_NUMBER]
    for path in stat_paths:
        if not (Path(path).is_file() and not Path(path).is_symlink()):
            with open(path,'w') as f:
                f.write(str(0))

def set_serial_number(nmb):
    lock.acquire()
    try:
        with open(SERIAL_NUMBER, 'w') as f:
            f.write(str(nmb))

    finally:
        lock.release()


def increase_issued_counter():
    lock.acquire()

    try:
        with open(ISSUED_COUNTER, 'r') as f:
            cnt = int(f.readline())

        with open(ISSUED_COUNTER, 'w') as f:
            f.write(str(cnt+1))
    finally:
        lock.release()


def increase_revoked_counter():
    lock.acquire()

    try:
        with open(REVOKED_COUNTER, 'r') as f:
            cnt = int(f.readline())

        with open(REVOKED_COUNTER, 'w') as f:
            f.write(str(cnt+1))
    finally:
        lock.release()

def get_issued_counter():
    try:
        with open(ISSUED_COUNTER, 'r') as f:
            counter = int(f.readline())
        return counter
    except:
        return -1


def get_revoked_counter():
    try:
        with open(REVOKED_COUNTER, 'r') as f:
            counter = int(f.readline())
        return counter
    except:
        return -1


def get_serial_number():
    try:
        with open(SERIAL_NUMBER, 'r') as f:
            data = f.read(1024)
            if data.isnumeric():
                return int(data)
            else:
                return -2
    except:
        return -1

def delete_privkey(key_path):
    if '/keys/' in key_path:
        # Only do something if it's locater in a folder keys somewhere
        lock.acquire()
        try:
            remove(key_path)
        finally:
            lock.release()

### CLASSES ##############################################

class DelayedRemovingThread(Thread):
    def __init__(self, time, path):
        Thread.__init__(self)
        self.time = time
        self.path = path

    def run(self):
        time.sleep(self.time)
        delete_privkey(self.path)
        return

### MAIN #################################################


def main():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_mapping(SECRET_KEY='k5Nok7EFhY')

    # Save logs to file
    logging.basicConfig(level=logging.DEBUG)
    init_logger = logging.getLogger('init_server')
    werkzeug_logger = logging.getLogger('werkzeug')
    handler = logging.FileHandler(LOG_PATH)
    init_logger.addHandler(handler)
    werkzeug_logger.addHandler(handler)
    app.logger.addHandler(handler)

    init_ca_server(app.logger)
    ssl_ctx = create_ssl_context()

    # Define access urls

    @app.route('/get_new_cert', methods=['POST'])
    # TODO: don't forget to remove the created private key in the end after a delay to keep it in the backup server
    # Check https://www.admin-enclave.com/en/articles/windows/422-how-to-create-a-pkcs12-file-with-a-ordered-certificate-chain.html
    def gen_new_cert():
        # Get user data from the posted json
        # user_info: `uid`, `first_name`, `last_name`, `mail_address`
        user_info = request.get_json()

        # Check if not already issued or has been revoked (none valid), else we can issue a new one
        cert = get_cert_from_uid(user_info['uid'])
        if cert is not None:
            # already issued
            return 'ALREADY_ISSUED'

        # Create a new cert
        current_user_inter = get_curr_intermediate_ca_user()
        curr_user_inter_cert_path = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + current_user_inter + '/' + current_user_inter + INTERMEDIATE_SUFFIX_CERT_NAME
        curr_user_inter_cert = get_cert_from_file(curr_user_inter_cert_path)
        curr_user_inter_key_path = ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + current_user_inter + INTERMEDIATE_SUFFIX_PRIVKEY_NAME
        curr_user_inter_key = get_key_from_file(curr_user_inter_key_path)
        cert, private_key = gen_user_cert(user_info['uid'], user_info['last_name'], user_info['first_name'], user_info['mail_address'], curr_user_inter_cert, curr_user_inter_key)

        # Save the cert and the key
        cert_path, key_path = get_cert_and_key_path(cert)
        save_certificate(cert, cert_path)
        save_key(private_key, key_path)

        set_serial_number(cert.serial_number)

        cert_chain = [cert_path, curr_user_inter_cert_path, ROOT_CERT_PATH]

        pkcs12_cert = gen_pkcs12(cert_chain, key_path)
        
        # Increase issued counter
        increase_issued_counter()

        # Delete the issued private key after 10 seconds
        t = DelayedRemovingThread(10, key_path)
        t.start()

        return pkcs12_cert

    # It receives a user certificate nad verifies it.
    # @app.route('/verify', methods=['POST'])
    # def verify_cert():
    #     # data required: the certificate to verify
        
    #     # Receive the cert to verify and store it temporarly
    #     cert = request.get_data()
    #     tmp_name = '/tmp/tmp_verification.crt'
    #     with open(tmp_name, 'wb') as f:
    #         f.write(cert)

    #     # Verify the certificate
    #     curr_inter_folder_path = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + get_curr_intermediate_ca_user() + '/'
    #     return verify_certificate(tmp_name, curr_inter_folder_path)


    @app.route('/authenticate_by_certificate', methods=['POST'])
    def auth_by_cert():
        # data required: a uid, a challenge and a signed challenge that we will compare with
        
        # Receive the data to verify
        uid = request.json['uid']
        challenge = request.json['challenge']
        signed_challenge = request.json['signed_challenge']

        cert = get_cert_from_uid(uid)
        if cert is None:
            return 'False'

        public_key = cert.public_key()
        
        # Verify the challenge
        try:
            crypto.verify(cert, b64.b64decode(signed_challenge), challenge.encode(), 'sha256')
        except crypto.Error:
            return 'False'

        # Verify certificate validity

        curr_inter_folder_path = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + get_curr_intermediate_ca_user() + '/'
        cert_path, _ = get_cert_and_key_path(cert)
        return str(verify_certificate(cert_path, curr_inter_folder_path))


    @app.route('/revoke', methods=['POST'])
    def revoke_cert():
        uid = request.json['uid']
        cert = get_cert_from_uid(uid)
        if cert is not None:
            curr_inter_ca_user = get_curr_intermediate_ca_user()
            curr_inter_folder_path = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + curr_inter_ca_user + '/'
            crl = CRL(folder_path=curr_inter_folder_path,
                cert_path=curr_inter_folder_path+curr_inter_ca_user+INTERMEDIATE_SUFFIX_CERT_NAME,
                private_key_path=ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + curr_inter_ca_user + INTERMEDIATE_SUFFIX_PRIVKEY_NAME)
            crl.update_crl(cert)
            increase_revoked_counter()

            # Read crl and return the new crl
            with open(curr_inter_folder_path + CRL_NAME, 'r') as crl_f:
                data = crl_f.read()

            return data

    @app.route('/get_stats', methods=['GET'])
    def get_stats():
        stats = {
            'issued': get_issued_counter(),
            'revoked': get_revoked_counter(),
            'serial_number': get_serial_number()
        }
        return stats

    app.run(
        host=IP_CA_SRV,
        port=PORT_CA_SRV,
        ssl_context=ssl_ctx,
        threaded=True)


if __name__ == '__main__':
    main()
