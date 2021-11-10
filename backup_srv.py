import socket
import ssl
import logging
from os import rename, remove
from os.path import exists
from datetime import datetime
from threading import Thread, Lock

# My files
from ASL_config import *


# Backup paths
HOME = '/home/backup_user/'
TEST_PATH = HOME+'test/' # TODO: delete this
LOG_PATH = HOME + 'logs/'
WEBSRV_BACKUP_PATH = HOME + 'websrv_backup/'
CA_BACKUP_PATH = HOME + 'CA_backup/'
DB_BACKUP_PATH = HOME + 'DB_backup/'
FIREWALL_BACKUP_PATH = HOME + 'firewall_backup/'

# SSL context creation
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain(backup_cert_path, backup_priv_key_path)
ssl_ctx.load_verify_locations(ca_cert_path)
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

# Misc.
err_prefix = 'ERR: '
BUFSIZE = 1024

lock=Lock()

logging.basicConfig(level=logging.INFO)
backup_log = logging.getLogger('backup_logger')
backup_log.setLevel(logging.DEBUG)


### FUNCTIONS ########################################

def get_timestamp():
    return str(datetime.now().strftime('%d.%m.%Y-%H:%M:%S'))

def get_folder_from_ip(ip_addr):
    if ip_addr == TEST_IP: # TODO: delete this
        return TEST_PATH # TODO: delete this
    elif ip_addr == WEBSRV_IP:
        return WEBSRV_BACKUP_PATH
    elif ip_addr == CA_IP:
        return CA_BACKUP_PATH
    elif ip_addr == DB_IP:
        return DB_BACKUP_PATH
    elif ip_addr == FIREWALL_IP:
        return FIREWALL_BACKUP_PATH
    else:
        return None

def gen_backup_name(backup_folder, filename):
    return backup_folder + filename + '.BACKUP-' + get_timestamp()

def event_failed_backup_to_log(e, ip_addr):
    with open(LOG_PATH, 'a') as f:
        f.writelines(err_prefix + 'backup failed for ip' + ip_addr + '\n\tError: '+str(e))

def append_changes(tmp_path, backup_path):
    if exists(backup_path):
        # Read last line
        with open(backup_path, 'r') as backup_f_read:
            for line in backup_f_read:
                pass
            last_line = line.strip()

        start_write = False

        with open(backup_path, 'a') as backup_f_append:
            with open(tmp_path, 'r') as tmp_f:
                for line in tmp_f:
                    if start_write:
                        backup_f_append.write(line)
                    elif line.strip() == last_line:
                        start_write = True
    else:
        # The file does not already exists ==> create it
        rename(tmp_path, backup_path)

    # Remove tmp file
    if exists(tmp_path):
        remove(tmp_path)


def backup(conn, ip_addr):
    # Get destination folder
    backup_folder = get_folder_from_ip(ip_addr)
    if backup_folder is None:
        conn.close()
        backup_log.debug(err_prefix+'unknown IP: '+ip_addr)
        return

    # Get name from connection
    data_recv = conn.recv(BUFSIZE)
    backup_log.debug('data_recv: '+str(data_recv))
    data_split = data_recv.split(' '.encode('utf-8'))
    filename = data_split[0].decode('utf-8')
    try:
        log_indication = data_split[1].decode('utf-8') #if log, then value='log'
    except Exception as e:
        log_indication = None

    # If log => append; else create new file
    is_log = (log_indication == 'log')
    if is_log:
        dest_path = backup_folder+'tmp_log'
    else:
        dest_path = gen_backup_name(backup_folder, filename)

    # Start receiving data and writing to file ==> beware of concurrence ==> lock
    lock.acquire()

    try:
        with open(dest_path, 'wb') as f:
            data = conn.recv(BUFSIZE)
            while data:
                f.write(data)
                data = conn.recv(BUFSIZE)

        # if it's log, then append to already created file
        if is_log:
            real_log_path = backup_folder + filename + '.BACKUP'
            append_changes(dest_path, real_log_path)

    except Exception as e:
        backup_log.debug(err_prefix+'error in backup server: '+e)
        event_failed_backup_to_log(e, ip_addr)

    finally:
        lock.release()
        conn.close()

    return


### CLASSES ##########################################

class BackupThread(Thread):
    def __init__(self, connection, ip_addr):
        super(BackupThread, self).__init__()
        self.connection = connection
        self.ip_addr = ip_addr

    def run(self):
        backup(self.connection, self.ip_addr)
        return

### MAIN #############################################
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((BACKUP_SRV_IP, BACKUP_SRV_PORT))
        sock.listen(5)
        with ssl_ctx.wrap_socket(sock, server_side=True) as ssock:

            while True:
                conn, addr = ssock.accept()

                backup_log.info('Connection from '+ str(addr) + ' at ' + get_timestamp())

                # Create a thread for backup
                try:
                    thread = BackupThread(conn, addr[0])
                    thread.start()
                except:
                    backup_log.debug(err_prefix + 'error while processing connection ' +
                          str(conn))


if __name__ == '__main__':
    main()
