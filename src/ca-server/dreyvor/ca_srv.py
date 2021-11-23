import ssl
import logging
from pathlib import Path
from flask import Flask, request, send_from_directory

# My files
from ca_core import *
from ca_config import *

### SSL Context ##########################################

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
    if root_already_existant:
        try:
            inter_user_cert = get_cert_from_file(INTERMEDIATE_USER_CERT_PATH)
            inter_user_key = get_key_from_file(INTERMEDIATE_USER_PRIVKEY_PATH)
            inter_user_already_existant = True
        except Exception as e:
            logger.info(
                '!!! WARNING !!!\nINTERMEDIATE USER CERTIFICATE NON-EXISTENT, WE CREATE A NEW ONE'
                + ' ' + str(e))
            inter_user_cert, inter_user_key = gen_intermediate_ca(USER_FOLDER_NAME, root_cert, root_key, init_phase=True)
            save_certificate(inter_user_cert, INTERMEDIATE_USER_CERT_PATH)
            save_key(inter_user_key, INTERMEDIATE_USER_PRIVKEY_PATH)
    else:
        logger.info(
            '!!! WARNING !!!\nINTERMEDIATE TLS CERTIFICATE EXISTS WITH AN OLD ROOT, WE CREATE A NEW ONE'
        )
        inter_user_cert, inter_user_key = gen_intermediate_ca(USER_FOLDER_NAME, root_cert, root_key, init_phase=True)
        save_certificate(inter_user_cert, INTERMEDIATE_USER_CERT_PATH)
        save_key(inter_user_key, INTERMEDIATE_USER_PRIVKEY_PATH)
    # Write current user intermediate name
    set_curr_intermediate_ca_user(USER_FOLDER_NAME)


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
            TLS_cert, TLS_key = gen_TLS_cert(srv_ip, inter_TLS_cert, inter_TLS_key)
            save_certificate(TLS_cert, cert_path)
            save_key(TLS_key, key_path)

        # Generate TLS certificate chain to verify identity
        file_paths_for_CA_chain = [cert_path, INTERMEDIATE_TLS_CERT_PATH, ROOT_CERT_PATH]
        with open(INTERMEDIATE_TLS_FOLDER + ISSUED_FOLDER_NAME + srv_name + SUFFIX_CERT_CHAIN_NAME, 'w') as outfile:
            for fname in file_paths_for_CA_chain:
                with open(fname) as infile:
                    outfile.write(infile.read())

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
    # TODO: don't forget to remove the created private key in the end
    # TODO: send the certificate in PKCS12 format
    def gen_new_cert():
        user_info = request.json

    @app.route('/verify', methods=['POST'])
    def verify_cert():
        return NotImplementedError

    @app.route('/revoke', methods=['POST'])
    def revoke_cert():
        return NotImplementedError

    @app.route('/get_stats', methods=['GET'])
    def get_stats():
        return NotImplementedError

    # @app.route('/favicon.ico')
    # def favicon():
    #     return send_from_directory(HOME,
    #                                'favicon.ico',
    #                                mimetype='image/vnd.microsoft.icon')

    app.run(
        host=IP_CA_SRV,
        port=PORT_CA_SRV,
        ssl_context=None,  # TODO: enable ssl_ctx
        threaded=True)


if __name__ == '__main__':
    main()
