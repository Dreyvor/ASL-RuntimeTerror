### Network ###
#IP_CA_SRV = '192.168.10.10'
IP_CA_SRV = '127.0.0.1'  # TODO: change this ip for the one of the ca-server
PORT_CA_SRV = 8080

### Certificates validity ###
validity_root_days = 10 * 365
validity_intermediate_days = 5 * 365
validity_user_days = 365
validity_TLS_days = 365

### Paths ###
# TODO: change home folder
# HOME = '/home/ca-server/'
HOME = '/home/brad/Documents/EPFL/SYSCOM/MA04-ETHZ/Applied_security_laboratory/project/runtime_terror/src/ca-server/dreyvor/simulated_home_folder/'

CERTIFICATES_PATH = HOME + 'certificates/'
CERT_CHAIN_PATH = CERTIFICATES_PATH + 'CA_chain.crt'

ROOT_FOLDER = CERTIFICATES_PATH + 'root/'
ROOT_CERT_PATH = ROOT_FOLDER + 'root.crt'  # file
ROOT_PRIVKEY_PATH = ROOT_FOLDER + 'root.pem'  # file

INTERMEDIATE_FOLDER = CERTIFICATES_PATH + 'intermediate/'
INTERMEDIATE_CERT_PATH = INTERMEDIATE_FOLDER + 'inter.crt'  # file
INTERMEDIATE_PRIVKEY_PATH = INTERMEDIATE_FOLDER + 'inter.pem'  # file

ISSUED_PATH = CERTIFICATES_PATH + 'issued/'  # Path to a folder
REVOKED_PATH = CERTIFICATES_PATH + 'revoked/'  # Path to a folder
PRIVKEYS_PATH = HOME + 'keys/'  # Path to a folder

LOG_PATH = HOME + 'ca-server.log'  # log of the ca-server (the path is the same as the code of the server)

CA_STAT_PATH = HOME + 'admin_stats/'  # path to a folder
ISSUED_COUNTER = CA_STAT_PATH + 'issued.txt'  # file
REVOKED_COUNTER = CA_STAT_PATH + 'revoked.txt'  # file
SERIAL_NUMBER = CA_STAT_PATH + 'serial_number.txt'  # file

### TLS ###
TLS_FOLDER_PATH = HOME + 'TLS/'
TLS_CERT_PATH = TLS_FOLDER_PATH + 'ca_server.crt'
TLS_CERT_CHAIN_PATH = TLS_FOLDER_PATH + 'ca_server_CA_chain.crt'
TLS_KEY_PATH = TLS_FOLDER_PATH + 'ca_server.pem'
TLS_ROOT_CERT_PATH = ROOT_CERT_PATH

NEED_TO_EXISTS = [
    HOME, ROOT_FOLDER, INTERMEDIATE_FOLDER, ISSUED_PATH, REVOKED_PATH,
    PRIVKEYS_PATH, CA_STAT_PATH, TLS_FOLDER_PATH
]
