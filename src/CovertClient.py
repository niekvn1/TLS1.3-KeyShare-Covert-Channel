from ClientHello import ClientHello
from TLSClient import TLSClient
from TLSValues import SUPPORTED_GROUP_X25519, SUPPORTED_GROUP_SECP521R1, \
    SUPPORTED_GROUPS, ECPARAMS, XPARAMS, FFDHEPARAMS, \
    GROUP_X, GROUP_SECP, GROUP_FFDHE, \
    TLS_ALERT_RECORD_TYPE, ALERT_LEVEL_FATAL
from Utils import printBytes, loadPublicKey, booleansToBits, AESCipher
from modular import hasModSqrt, modular_sqrt
from Covert import COVERT_KEY_LENGTHS, SYMMETRIC_KEY, NAME_TO_GROUP_MAP
from math import log, ceil
from time import sleep
from os import urandom
import socket
import fcntl
import ctypes
import struct

class CovertClient:
    def __init__(self, servername, port, key=True, encrypt=True, groups=SUPPORTED_GROUPS, symkey=SYMMETRIC_KEY, verbose=False):
        self.key = self.__genKey__(key)
        self.groups = groups
        self.encrypt = encrypt
        self.tlsClient = TLSClient(servername, port)
        self.cipher = AESCipher(symkey)
        self.verbose = verbose


    def __genKey__(self, key):
        if key:
            return loadPublicKey(SUPPORTED_GROUP_X25519, "client_crypto/x25519public.key.pem")
        else:
            return None


    def __secpCovertKey__(self, group, byteArray):
        """
        For a the given byte array, find a close x that is a quadratic residue.
        Find the y for the found x (y^2 = x^3 + ax + b).
        Return b'04<x><y>'.

        The maximum offset is 255, to make this fit in one byte.
        """
        params = ECPARAMS[group]
        p = params[0]
        a = params[1]
        b = params[2]
        x_guess = int.from_bytes(byteArray, 'big')
        y = None
        bigger_than_p = x_guess >= p
        for i in range(0, 256):
            x = (x_guess + i) % p
            y_pow = (pow(x, 3, p) + x * a + b) % p
            if hasModSqrt(y_pow, p):
                y = modular_sqrt(y_pow, p)
                offset = i
                break;

        if y is None:
            # TODO: Handle this fairy unlikely case
            return None, None
        else:
            l = COVERT_KEY_LENGTHS[group]
            if group == SUPPORTED_GROUP_SECP521R1:
                l += 1
            if (x > p):
                print("Error: invalid X")

            return b'\x04' + x.to_bytes(l, 'big') + y.to_bytes(l, 'big'), offset, bigger_than_p

    def __xCovertKey__(self, group, byteArray):
        params = XPARAMS[group]
        l = COVERT_KEY_LENGTHS[group]
        p = params[0]
        x_guess = int.from_bytes(byteArray, 'big')
        bigger_than_p = x_guess >= p
        x = x_guess % p

        return x.to_bytes(l, 'big'), bigger_than_p

    def __ffdheCovertKey__(self, group, byteArray):
        params = FFDHEPARAMS[group]
        l = COVERT_KEY_LENGTHS[group]
        p = params[0]
        y_guess = int.from_bytes(byteArray, 'big')
        bigger_than_p = y_guess >= p
        y = y_guess % p
        if y == 0:
            offset = 0x01
            y += 2
        elif y == 1:
            offset = 0x02
            y += 1
        elif y == p - 1:
            offset = 0x03
            y -= 1
        else:
            offset = 0

        return y.to_bytes(l, 'big'), offset, bigger_than_p

    def __covertKeys__(self, byteArray):
        if self.key is None:
            covertGroups = self.groups
            covertKeys = {}
        else:
            covertGroups = self.groups[1:]
            covertKeys = {self.groups[0]: self.key}

        x_offsets = []
        x_biggers = []
        offset = 0
        for group in covertGroups:
            l = COVERT_KEY_LENGTHS[group]
            if group in GROUP_SECP:
                key, x_offset, bigger_than_p = self.__secpCovertKey__(group, byteArray[offset:offset + l])
                x_offsets.append(x_offset)
                x_biggers.append(bigger_than_p)
                if key is None:
                    print("Error: no quadratic residue found with offset less than 256")
                else:
                    covertKeys[group] = key
            elif group in GROUP_X:
                covertKeys[group], bigger_than_p = self.__xCovertKey__(group, byteArray[offset:offset + l])
                x_biggers.append(bigger_than_p)
            elif group in GROUP_FFDHE:
                key, x_offset, bigger_than_p = self.__ffdheCovertKey__(group, byteArray[offset:offset + l])
                x_offsets.append(x_offset)
                x_biggers.append(bigger_than_p)
                covertKeys[group] = key
            offset += l
        return covertKeys, x_offsets, x_biggers

    def __encodeSessionID__(self, x_offsets, x_biggers, nonce):
        bigger_bits = booleansToBits(x_biggers)
        arrays = []
        for offset in x_offsets:
            arrays.append(offset.to_bytes(1, 'big'))

        arrays.append(bigger_bits.to_bytes(2, 'big'))
        sessionID = bytearray(32 - sum([len(b) for b in arrays]))  + b''.join(arrays)
        if self.encrypt:
            sessionID = self.cipher.encrypt(sessionID, nonce)
        return sessionID


    def __hello__(self, byteArray):
        """
        This function sends one hello message, with the available key sizes
        as number of bytes.
        """
        nonce=None
        if self.encrypt:
            nonce = urandom(32)
            byteArray = self.cipher.encrypt(byteArray, nonce)

        keys, x_offsets, x_biggers = self.__covertKeys__(byteArray)
        sessionID = self.__encodeSessionID__(x_offsets, x_biggers, nonce)

        self.tlsClient.connect()
        self.tlsClient.hello(keys, sessionID, nonce=nonce)

    def __fragment__(self, byteArray):
        """
        Split the bytearray in fragments such that each fragment fits in
        one Client Hello. If needed, padding is added.
        """
        if self.key is None:
            maxLength = sum([COVERT_KEY_LENGTHS[group] for group in self.groups])
        else:
            maxLength = sum([COVERT_KEY_LENGTHS[group] for group in self.groups[1:]])

        l = len(byteArray)
        dataLength = maxLength - 1
        rest = l % dataLength
        fragments = []
        offset = 0
        while offset + dataLength < l:
            fragments.append(b'\xff' + byteArray[offset:offset + dataLength])
            offset += dataLength

        if offset + dataLength == l:
            fragments.append(b'\x01' + byteArray[offset:offset + dataLength])
            offset += dataLength
        else:
            paddingBytes = (maxLength - rest)
            bitCount = ceil(log(paddingBytes + 1, 2))
            byteCount = (bitCount // 8)
            if bitCount % 8 != 0:
                byteCount += 1

            paddings = []
            tmp = paddingBytes
            while tmp > 254:
                paddings.append(b'\x00')
                tmp -= 254
            paddings.append(tmp.to_bytes(1, 'big'))
            fragments.append(b''.join(paddings) + bytearray(paddingBytes - len(paddings)) + byteArray[-(rest):])

        return fragments

    def send(self, byteArray):
        fragments = self.__fragment__(byteArray)
        for f in fragments:
            self.__hello__(f)

    def recv(self):
        record = self.tlsClient.recv()
        if record is None:
            return None
        elif record.getType() == TLS_ALERT_RECORD_TYPE and \
                record.getAlertLevel() == ALERT_LEVEL_FATAL:
            self.tlsClient.close()
            return record

    def sendrecv(self, byteArray):
        fragments = self.__fragment__(byteArray)
        if self.verbose:
            print(f"Sending {len(byteArray)} bytes...")
            printBytes(byteArray)

        for f in fragments:
            self.__hello__(f)
            self.recv()


# class ifreq(ctypes.Structure):
#     """
#     Source: https://github.com/zeigotaro/python-sniffer/blob/master/snifferCore.py
#     """
#     _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
#                 ("ifr_flags", ctypes.c_short)]

class FLAGS(object):
  # linux/if_ether.h
  ETH_P_ALL     = 0x0003 # all protocols
  ETH_P_IP      = 0x0800 # IP only
  # linux/if.h
  IFF_PROMISC   = 0x100
  # linux/sockios.h
  SIOCGIFFLAGS  = 0x8913 # get the active flags
  SIOCSIFFLAGS  = 0x8914 # set the active flags


def unpack(frame):
    """
    Source: https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf
    """
    dest, src, prototype = struct.unpack('! 6s 6s H', frame[:14])
    if prototype == FLAGS.ETH_P_IP:
        return prototype, frame[14:]
    else:
        print("Error: unsupported ethertype")


def rawInput(interface, cc):
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(FLAGS.ETH_P_ALL))
    rawSocket.bind((interface, 0))
    count = 0

    # ifr = ifreq()
    # ifr.ifr_ifrn = interface.encode("ASCII")
    # fcntl.ioctl(rawSocket, FLAGS.SIOCGIFFLAGS, ifr) # get the flags
    # ifr.ifr_flags |= FLAGS.IFF_PROMISC # add the promiscuous flag
    # fcntl.ioctl(rawSocket, FLAGS.SIOCSIFFLAGS, ifr) # update

    while True:
        data = rawSocket.recvfrom(8192)
        count += 1
        tmp = unpack(data[0])
        if tmp is None:
            continue

        prototype, packet = tmp
        cc.sendrecv(packet)


def test(cc):
    msg = b''.join([b'\xff' for _ in range(3176)])
    cc.sendrecv(msg)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='TLS 1.3 Covert Channel')
    parser.add_argument('--encrypt', action='store_true', help='Enable encryption')
    parser.add_argument('--key', action='store_true', help='Use one public key as an actual TLS key')
    parser.add_argument('-g', '--group', action='append')
    parser.add_argument('--test', action='store_true', help='Send a test message')
    parser.add_argument('-s', '--server', help='The server IP or domain.')
    parser.add_argument('-p', '--port', type=int, choices=range(1, 65536), help='The server port.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Output all (unencrypted) bytes sent to the covert channel server to stdout')
    args = parser.parse_args()

    if args.server is None or args.port is None:
        print("Usage: python3 CovertClient.py -s <server IP/Domain> -p <server port> [--encrypt] -g <group> -g <group> -g ...")
        exit(1)
    elif args.group is None:
        supportedGroups = SUPPORTED_GROUPS
    else:
        supportedGroups = []
        for group in args.group:
            if group.lower() not in NAME_TO_GROUP_MAP.keys():
                print(f"Supported Groups: {NAME_TO_GROUP_MAP.keys()}")
                exit(1)
            supportedGroups.append(NAME_TO_GROUP_MAP[group])

    cc = CovertClient(args.server, args.port, key=args.key, encrypt=args.encrypt, groups=supportedGroups, verbose=args.verbose)
    if args.test:
        test(cc)
    else:
        rawInput("tlsc", cc)
