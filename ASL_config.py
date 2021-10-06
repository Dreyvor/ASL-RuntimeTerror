from os import getcwd

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
BACKUP_SRV_IP, BACKUP_SRV_PORT= '127.0.0.1', 8888