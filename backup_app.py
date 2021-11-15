"""
Backup application that will be deployed on the different machines that need to be backup
"""

# Being to backup folder entirely
# Keep last X versions of a file

import socket
import ssl
import logging
import json
import argparse
from os import remove
from os.path import basename
from threading import Thread
from time import sleep
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# My files
from ASL_config import *
import utils

# Read and parse arguments
parser = argparse.ArgumentParser(description='Backup agent')
parser.add_argument('-c', '--config_file_path', metavar='cfg_path', type=str, default='/etc/backup_agent.cfg', help='The path to the JSON config file (default: /etc/backup_agent.cfg)')
args = parser.parse_args()
print(args.config_file_path)

# Read the JSON config file
try:
    with open(args.config_file_path, 'r') as f:
        cfg = json.load(f)
except Exception as e:
    print(err_prefix + 'error when trying to read the config file. Check the path and file rights:\n\t' + str(e))
    exit(-1)

# Configure logger
logging.basicConfig(level=logging.INFO)
backup_agent_log = logging.getLogger('backup_agent_' + cfg['logger_name'])
backup_agent_log.setLevel(logging.DEBUG)
backup_agent_log.info('Logger is started')

## SSL context
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# TODO: next line is faulty, I need the cert of the server using this agent.
ssl_ctx.load_cert_chain(cfg['TLS_cert_path'], cfg['TLS_private_key_path'])
ssl_ctx.load_verify_locations(cfg['root_ca_path'])
ssl_ctx.verify_mode = ssl.CERT_REQUIRED
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

### CLASSES ##########################################
# Thanks to https://www.michaelcho.me/article/using-pythons-watchdog-to-monitor-changes-to-a-directory

class EventHandler(FileSystemEventHandler):
    def __init__(self, is_log, need_enc):
        super(EventHandler, self).__init__()
        self.is_log = is_log
        self.need_enc = need_enc

    #@staticmethod
    def on_any_event(self, event):
        if event.is_directory:
            return None

        elif event.event_type == 'modified':
            start_backup(basename(event.src_path), event.src_path, self.is_log, self.need_enc)
        elif event.event_type == 'moved':
            start_backup(basename(event.src_path), event.dest_path,
                         self.is_log, self.need_enc)

        return


class Watcher():
    def __init__(self, path, is_log, need_enc):
        self.observer = Observer()
        self.path = path
        self.is_log = is_log
        self.need_enc = need_enc

    def run(self):
        event_handler = EventHandler(self.is_log, self.need_enc)
        self.observer.schedule(event_handler, self.path, recursive=True)
        self.observer.start()
        try:
            while True:
                sleep(5)
        except Exception as e:
            self.observer.stop()
            backup_agent_log.debug(
                err_prefix + 'error while watching file modifications:\n\t' +
                str(e))

        self.observer.join()


class WatcherThread(Thread):
    def __init__(self, watcher):
        super(WatcherThread, self).__init__()
        self.watcher = watcher

    def run(self):
        self.watcher.run()
        return


### FUNCTIONS ########################################

def encrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read(BUFSIZE)
        buffer = data
        while data:
            data = f.read(BUFSIZE)
            buffer += data

        data_encrypted = utils.encrypt(cfg['AES_encryption_key_path'], buffer)
        enc_file_path = '/tmp/' + basename(path) + '.encrypted'
        with open(enc_file_path, 'wb') as ef:
            ef.write(data_encrypted)

    return enc_file_path


def start_backup(filename, path, is_log, need_enc):
    # SOCKET HTTPS with TLSv1.3 only
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with ssl_ctx.wrap_socket(sock, server_hostname=cfg['backup_srv_ip']) as ssock:
            ssock.settimeout(1)

            try:
                ssock.connect((cfg['backup_srv_ip'], cfg['backup_srv_port']))

                # Send filename and an indication if it's log or not
                first_packet_str = filename + ' ' + str(is_log)
                first_packet = first_packet_str.encode('utf-8')
                ssock.send(first_packet)
                backup_agent_log.info('First packet sent: ' + first_packet_str)

                # Encrypt the file if it's needed
                if need_enc:
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
                if need_enc:
                    remove(path_to_send)

            except Exception as e:
                backup_agent_log.debug(err_prefix +
                                       'error when trying to backup path: ' +
                                       path + '\n\t' + str(e))

            # do not allow any more transmissions
            ssock.shutdown(socket.SHUT_RDWR)

    return


### MAIN #############################################
def main():
    for to_backup in cfg['files_to_backup']:
        if(to_backup['is_log'] and to_backup['need_encryption']):
            backup_agent_log.info(err_prefix + 'Impossible to encrypt logs, since we use append to end of file...\nPlease correct that for: '+ to_backup['path'])
            exit(1)
        try:
            t = WatcherThread(Watcher(to_backup['path'], to_backup['is_log'], to_backup['need_encryption']))
            t.start()
        except Exception as e:
            backup_agent_log.debug(err_prefix +
                                   'error when starting observer thread:\n\t' +
                                   str(e))


if __name__ == '__main__':
    main()
