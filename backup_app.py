"""
Backup application that will be deployed on the different machines that need to be backup
"""

import socket
import ssl
from os import getcwd
from ASL_config import *

#### SSL context
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_ctx.load_cert_chain(backup_cert_path, backup_priv_key_path)
ssl_ctx.load_verify_locations(ca_cert_path)
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
#ssl_ctx.options = ssl_ctx.maximum_version

# We cannot disable TLSv1.3 but we can restrict the use of any other ciphers to the first recommended by "ssl_ctx.get_ciphers()"
# "ECDHE-ECDSA-AES256-GCM-SHA384" is also recommended by https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
#ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
	with ssl_ctx.wrap_socket(sock, server_hostname=BACKUP_SRV_IP) as ssock:
		ssock.connect((BACKUP_SRV_IP, BACKUP_SRV_PORT))
		print(ssock.version())

print('No problem encountered!\nWe correctly stopped the connection!')
