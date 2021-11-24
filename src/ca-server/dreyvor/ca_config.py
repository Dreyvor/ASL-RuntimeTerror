### Network ###
#IP_CA_SRV = '192.168.10.10'
IP_CA_SRV = '127.0.0.1'  # TODO: change this ip for the one of the ca-server
PORT_CA_SRV = 8080

### Certificates validity ###
validity_root_days = 10 * 365
validity_intermediate_days = 5 * 365
validity_user_days = 365
validity_TLS_days = 365

### FILE OR FOLDER NAMES ###
## File names
SUFFIX_CERT_CHAIN_NAME = '_CA_chain.crt'
INTERMEDIATE_SUFFIX_CERT_NAME = '_inter.crt'
INTERMEDIATE_SUFFIX_PRIVKEY_NAME = '_inter.pem'

## Folder names
INTERMEDIATE_FOLDER_PREFIX = 'iMoviesIntermediate_'

# Will be created for each new certificate authority (not finally issued cert)
ISSUED_FOLDER_NAME = 'issued/'  # a folder's name
REVOKED_FOLDER_NAME = 'revoked/'  # a folder's name
PRIVKEYS_FOLDER_NAME = 'keys/'  # a folder's name

### Paths ###
# TODO: change home folder
# HOME = '/home/ca-server/'
HOME = '/home/brad/Documents/EPFL/SYSCOM/MA04-ETHZ/Applied_security_laboratory/project/runtime_terror/src/ca-server/dreyvor/simulated_home_folder/'

CERTIFICATES_PATH = HOME + 'certificates/'

# Root
ROOT_FOLDER = CERTIFICATES_PATH + 'root/'
ROOT_CERT_PATH = ROOT_FOLDER + 'root.crt'  # file
ROOT_PRIVKEY_PATH = ROOT_FOLDER + 'root.pem'  # file
ROOT_ORGANIZATION_NAME = 'iMoviesRootCA'

# TLS
TLS_FOLDER_NAME = 'TLS'
INTERMEDIATE_TLS_FOLDER = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + TLS_FOLDER_NAME + '/'
INTERMEDIATE_TLS_CERT_PATH = INTERMEDIATE_TLS_FOLDER + TLS_FOLDER_NAME + INTERMEDIATE_SUFFIX_CERT_NAME  # file
INTERMEDIATE_TLS_PRIVKEY_PATH = ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + TLS_FOLDER_NAME + INTERMEDIATE_SUFFIX_PRIVKEY_NAME  # file
TLS_CA_SRV_NAME, TLS_CA_SRV_IP = 'ca-server', '192.168.10.10'
TLS_DB_SRV_NAME, TLS_DB_SRV_IP = 'db-server', '192.168.10.30'
TLS_WEB_SRV_NAME, TLS_WEB_SRV_IP = 'web-server', '192.168.20.10'
TLS_BACKUP_SRV_NAME, TLS_BACKUP_SRV_IP = 'backup-server', '192.168.10.20'
TLS_FIREWALL_SRV_NAME, TLS_FIREWALL_SRV_IP = 'firewall-server', '192.168.10.1'

# USER
USER_FOLDER_NAME = 'USER'
INTERMEDIATE_USER_FOLDER = ROOT_FOLDER + ISSUED_FOLDER_NAME + INTERMEDIATE_FOLDER_PREFIX + USER_FOLDER_NAME + '/'
INTERMEDIATE_USER_CERT_PATH = INTERMEDIATE_USER_FOLDER + USER_FOLDER_NAME + INTERMEDIATE_SUFFIX_CERT_NAME  # file
INTERMEDIATE_USER_PRIVKEY_PATH = ROOT_FOLDER + PRIVKEYS_FOLDER_NAME + USER_FOLDER_NAME + INTERMEDIATE_SUFFIX_PRIVKEY_NAME  # file

# Misc.
LOG_PATH = HOME + 'ca-server.log'  # log of the ca-server (the path is the same as the code of the server)
CURRENT_USER_INTERMEDIATE_NAME_FILE_PATH = HOME + 'current_user_intermediate.txt'
CA_STAT_PATH = HOME + 'admin_stats/'  # path to a folder
ISSUED_COUNTER = CA_STAT_PATH + 'issued.txt'  # file
REVOKED_COUNTER = CA_STAT_PATH + 'revoked.txt'  # file
SERIAL_NUMBER = CA_STAT_PATH + 'serial_number.txt'  # file
CRL_NAME = 'crl.pem' # file name

TLS_CERTS_NEEDED = [
    (TLS_CA_SRV_NAME, TLS_CA_SRV_IP),
    (TLS_DB_SRV_NAME, TLS_DB_SRV_IP),
    (TLS_WEB_SRV_NAME, TLS_WEB_SRV_IP),
    (TLS_BACKUP_SRV_NAME, TLS_BACKUP_SRV_IP),
    (TLS_FIREWALL_SRV_NAME, TLS_FIREWALL_SRV_IP)]

FOLDERS_THAT_NEED_TO_EXISTS = [HOME, ROOT_FOLDER, ROOT_FOLDER + ISSUED_FOLDER_NAME, ROOT_FOLDER + REVOKED_FOLDER_NAME, ROOT_FOLDER + PRIVKEYS_FOLDER_NAME, CA_STAT_PATH]
