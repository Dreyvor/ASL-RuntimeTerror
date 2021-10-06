import socket
import ssl
from os import getcwd
from ASL_config import *

ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain(backup_cert_path, backup_priv_key_path)
ssl_ctx.load_verify_locations(ca_cert_path)
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
#ssl_ctx.options = ssl_ctx.maximum_version


with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((BACKUP_SRV_IP, BACKUP_SRV_PORT))
    sock.listen(5)
    with ssl_ctx.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()

        print('Connection from', str(addr))
        print(str(conn))