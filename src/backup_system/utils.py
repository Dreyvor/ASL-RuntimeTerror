from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

err_prefix = 'ERR: '
BUFSIZE = 1024

KEY_BYTE_LENGTH = 32
IV_BYTE_LENGTH = 8

### FUNCTIONS ########################################


def encrypt(key_path, data):
    with open(key_path, 'rb') as kf:
        key = kf.read(KEY_BYTE_LENGTH)

    rnd_generator = Random.new()
    iv = rnd_generator.read(IV_BYTE_LENGTH)
    int_iv = int.from_bytes(iv, byteorder='big')

    counter = Counter.new(128, initial_value=int_iv)

    aes = AES.new(key, AES.MODE_CTR, counter=counter)

    return iv + aes.encrypt(data)


def decrypt(key_path, data):
    int_iv = int.from_bytes(data[:IV_BYTE_LENGTH], byteorder='big')
    encrypted_data = data[IV_BYTE_LENGTH:]

    with open(key_path, 'rb') as kf:
        key = kf.read(KEY_BYTE_LENGTH)

    counter = Counter.new(128, initial_value=int_iv)
    aes = AES.new(key, AES.MODE_CTR, counter=counter)

    decrypted_data = aes.decrypt(encrypted_data)

    return decrypted_data
