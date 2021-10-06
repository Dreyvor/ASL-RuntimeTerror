import socket
import ssl

##### ROOT PATH
ROOT_PATH = '/home/brad/Documents/EPFL/SYSCOM/MA04-ETHZ/Applied_security_laboratory/project/runtime_terror'

##### BACKUP IP:PORT
BACKUP_SRV_IP, BACKUP_SRV_PORT= '127.0.0.1', 8888

##### SSL 
#### Paths for SSL
backup_cert_path = ROOT_PATH+'/local_certs/backup_srv_TLS_CSR_signed.pem'
backup_priv_key_path = ROOT_PATH+'/local_certs/backup_srv_TLS_CSR.key'
ca_cert_path = ROOT_PATH + '/local_certs/rootCA-cert.pem'

ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain(backup_cert_path, backup_priv_key_path)
ssl_ctx.load_verify_locations(ca_cert_path)
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
#ssl_ctx.options = ssl_ctx.maximum_version


with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('127.0.0.1', 8888))
    sock.listen(5)
    with ssl_ctx.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()

        print('Connection from', str(addr))
        print("ssock.family: "+ str(ssock.family))
        print("ssock.type: "+ str(ssock.type))
        print("ssock.proto: "+ str(ssock.proto))