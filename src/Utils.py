import base64
import json
from functools import reduce
from TLSValues import SUPPORTED_GROUP_X25519, SUPPORTED_GROUP_X448
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def printBytes(array):
    count = 0
    for byte in array:
        count += 1
        if count == 8:
            space = "  "
        elif count == 16:
            space = "\n"
            count = 0
        else:
            space = " "

        f = format(byte, "02x")
        print(f"{f}{space}", end="")
    if count != 0:
        print()


def decodePEM(filename):
    with open(filename, 'r') as keyfile:
        pem = keyfile.read()
        b64 = pem.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----\n", "")
        hexx = base64.b64decode(b64)
        return hexx
    keyfile.close()


def loadPublicKey(group, filename):
    hexx = decodePEM(filename)
    if group == SUPPORTED_GROUP_X25519:
        key = hexx[-32:]
    if group == SUPPORTED_GROUP_X448:
        key = hexx[-56:]
    return key


def loadPublicKeys(pairs):
    dictio = {}
    for group, filename in pairs:
        dictio[group] = loadPublicKey(group, filename)
    return dictio


def booleansToBits(booleans):
    return reduce(lambda a, b: (a<<1) + int(b), booleans)


def bitsToBooleans(integer, n):
    booleans = []
    for i in range(0, n):
        booleans.append(integer % 2 != 0)
        integer = integer >> 1
    booleans.reverse()
    return booleans


class AESCipher:
    def __init__(self, key):
        self.cipher = Cipher(algorithms.AES(key), None, backend=default_backend())

    def encrypt(self, data, nonce):
        self.cipher.mode = modes.GCM(nonce)
        enc = self.cipher.encryptor()
        cipherdata = enc.update(data)
        return cipherdata

    def decrypt(self, cipherdata, nonce):
        self.cipher.mode = modes.GCM(nonce)
        dec = self.cipher.decryptor()
        data = dec.update(cipherdata)
        return data
