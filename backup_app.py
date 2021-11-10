"""
Backup application that will be deployed on the different machines that need to be backup
"""

import socket
import ssl
import logging
from os import remove
from os.path import basename
from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# My files
from ASL_config import *
import utils  # TODO: Create utils

#### SSL context
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_ctx.load_cert_chain(backup_cert_path, backup_priv_key_path)
ssl_ctx.load_verify_locations(ca_cert_path)
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

# Read json for config
# TODO: read config
test_path = '/var/log/auth.log'  # TODO: delete this and read from config
test_is_log = True  # TODO: delete this and read from config
PATHS = [(test_path, test_is_log)]

test_logger_name = 'test'  # TODO: delete this and read from config
logging.basicConfig(level=logging.INFO)
backup_agent_log = logging.getLogger('backup_agent_' + test_logger_name)
backup_agent_log.setLevel(logging.DEBUG)

### CLASSES ##########################################
# Thanks to https://www.michaelcho.me/article/using-pythons-watchdog-to-monitor-changes-to-a-directory


class EventHandler(FileSystemEventHandler):
    def __init__(self, is_log):
        super(EventHandler, self).__init__()
        self.is_log = is_log

    #@staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        elif event.event_type == 'moved':
            start_backup(basename(event.src_path), event.src_path, self.is_log)
        elif event.event_type == 'modified':
            start_backup(basename(event.src_path), event.dest_path,
                         self.is_log)

        return


class Watcher():
    def __init__(self, path, is_log):
        self.observer = Observer()
        self.path = path
        self.is_log = is_log

    def run(self):
        event_handler = EventHandler(is_log)
        self.observer.schedule(event_handler, self.path, recursive=True)
        self.observer.start()
        try:
            while True:
                sleep(5)
        except Exception as e:
            self.observer.stop()
            backup_agent_log.debug(
                err_prefix + 'error while watching file modifications:\n\t' +
                e)

        self.observer.join()


class WatcherThread(Thread):
    def __init__(self, watcher):
        super(WatcherThread, self).__init__()
        self.watcher = watcher

    def run(self):
        self.watcher.run()
        return


### FUNCTIONS ########################################


def need_encryption(filename):
    #TODO: put that in json config file when describing files to backup
    return (".dump" in filename) or ("private" in filename)


def encrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read(BUFSIZE)
        buffer = data
        while data:
            data.read(BUFSIZE)
            buffer += data

        # TODO: Create utils and encrypt
        # TODO: Add key_path to json config file
        data_encrypted = utils.encrypt(key_path, buffer)
        enc_file_path = '/tmp/' + basename(path) + '.encrypted'
        with open(enc_file_path, 'wb') as ef:
            ef.write(data_encrypted)

        return enc_file_path


def start_backup(filename, path):
    # SOCKET HTTPS with TLSv1.3 only
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with ssl_ctx.wrap_socket(sock, server_hostname=BACKUP_SRV_IP) as ssock:
            ssock.settimeout(1)

            try:
                ssock.connect((BACKUP_SRV_IP, BACKUP_SRV_PORT))

                # Send filename and an indication if it's log or not
                first_packet = (filename + ' ' + str(is_log)).encode('utf-8')
                ssock.send(first_packet)
                backup_agent_log.info('filename sent: ' + first_packet)

                # Encrypt the file if it's needed
                if need_encryption(filename):
                    path_to_send = encrypt_file(path)
                else:
                    path_to_send = path

                # Send the file to backup server
                backup_agent_log.info(
                    'Sending (encrypted)? data to the backup server')
                with open(path_to_send, 'rb') as f:
                    data = f.read(BUFSIZE)
                    while data:
                        ssock.send(data)
                        data = f.read(BUFSIZE)

                backup_agent_log.info('Data sent ==> no backup issue')

                # Clean encrypted files
                if need_encryption(filename):
                    remove(path_to_send)

            except Exception as e:
                backup_agent_log.debug(err_prefix +
                                       'error when trying to backup path: ' +
                                       path + '\n\t' + e)

            # do not allow any more transmissions
            ssock.shutdown(socket.SHUT_RDWR)

    return


### MAIN #############################################
def main():
    for path, is_log in PATHS:
        try:
            t = WatcherThread(Watcher(p, is_log))
            t.start()
        except Exception as e:
            backup_agent_log.debug(err_prefix +
                                   'error when starting observer thread:\n\t' +
                                   e)


if __name__ == '__main__':
    main()
