from os import getcwd

# TODO: put everything in a config file

##### PATHS
ROOT_PATH = getcwd()
CERTS_PATH = ROOT_PATH + '/local_certs'

#### SSL 
### Certs
## Root
ca_cert_path = CERTS_PATH + '/rootCA-cert.pem'

## Backup 
backup_cert_path = CERTS_PATH + '/backup_srv_TLS_CSR_signed.pem'
backup_priv_key_path = CERTS_PATH + '/backup_srv_TLS_CSR.key'

##### IP:PORT
BACKUP_SRV_IP, BACKUP_SRV_PORT = '127.0.0.1', 8888 # TODO: modify this
WEBSRV_IP = '192.168.20.10'
CA_IP = '192.168.10.10'
DB_IP = '192.168.10.30'
FIREWALL_IP = '192.168.10.01'
#TEST_IP = '192.168.0.69' # TODO: delete this one
TEST_IP = '127.0.0.1' # TODO: delete this one

##### Misc.
err_prefix = 'ERR: '
BUFSIZE = 1024