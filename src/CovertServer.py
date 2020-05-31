from TLSServer import TLSServer
from Utils import loadPublicKey, printBytes, bitsToBooleans, AESCipher
from TLSValues import TLS_HANDSHAKE_RECORD_TYPE, HANDSHAKE_TYPE_CLIENT_HELLO, \
    SUPPORTED_GROUP_X25519, SUPPORTED_GROUP_SECP521R1, \
    ECPARAMS, XPARAMS, FFDHEPARAMS, GROUP_SECP, GROUP_FFDHE, GROUP_X
from Covert import COVERT_KEY_LENGTHS, SYMMETRIC_KEY
import socket

class CovertServer:
    def __init__(self, servername, port, key=None, validKey=True, encrypt=True, symkey=SYMMETRIC_KEY):
        self.key = key
        self.validKey = validKey
        self.encrypt = encrypt
        self.tlsServer = TLSServer(servername, port, key)
        self.cipher = AESCipher(symkey)

    def __secpCovertMessage__(self, group, key, offset, bigger_bool):
        l = COVERT_KEY_LENGTHS[group]
        if group == SUPPORTED_GROUP_SECP521R1:
            x = key[1:2 + l]    # Also take the ignored byte as because of overflow
        else:
            x = key[1:1 + l]

        p = ECPARAMS[group][0]
        x = (int.from_bytes(x, 'big') - offset) % p
        if bigger_bool:
            x += p
        return x.to_bytes(l, 'big')

    def __xCovertMessage__(self, group, key, bigger_bool):
        l = COVERT_KEY_LENGTHS[group]
        p = XPARAMS[group][0]
        x = int.from_bytes(key, 'big')
        if bigger_bool:
            x += p
        return x.to_bytes(l, 'big')

    def __ffdheCovertMessage__(self, group, key, offset, bigger_bool):
        l = COVERT_KEY_LENGTHS[group]
        p = FFDHEPARAMS[group][0]
        y = int.from_bytes(key, 'big')
        if offset != 0x00:
            if offset == 0x01:
                y -= 2
            elif offset == 0x02:
                y -= 1
            elif offset == 0x03:
                y += 1

        if bigger_bool:
            y += p
        return y.to_bytes(l, 'big')


    def __decodeSessionID__(self, chello):
        sessionID = chello.getSessionID()
        if self.validKey:
            covertGroups = chello.getKeyGroups()[1:]
        else:
            covertGroups = chello.getKeyGroups()

        keyCount = len(covertGroups)
        secpCount = sum([1 for group in covertGroups if group in GROUP_SECP or group in GROUP_FFDHE])
        if self.encrypt:
            sessionID = self.cipher.decrypt(sessionID, chello.getNonce())

        array = sessionID[-(secpCount + 2):]
        bigger_bools = bitsToBooleans(int.from_bytes(array[-2:], 'big'), keyCount)

        return [int.from_bytes(array[i:i + 1], 'big') for i in range(0, secpCount)], bigger_bools

    def __covertMessage__(self, chello):
        if self.validKey:
            covertGroups = chello.getKeyGroups()[1:]
            ckeys = chello.getKeys()[1:]
        else:
            covertGroups = chello.getKeyGroups()
            ckeys = chello.getKeys()

        msgs = []
        offsets, bigger_bools = self.__decodeSessionID__(chello)

        secpCount = 0
        for group, key, bigger_bool in zip(covertGroups, ckeys, bigger_bools):
            l = COVERT_KEY_LENGTHS[group]
            if group in GROUP_SECP:
                msgs.append(self.__secpCovertMessage__(group, key, offsets[secpCount], bigger_bool))
                secpCount += 1
            elif group in GROUP_X:
                msgs.append(self.__xCovertMessage__(group, key, bigger_bool))
            elif group in GROUP_FFDHE:
                msgs.append(self.__ffdheCovertMessage__(group, key, offsets[secpCount], bigger_bool))
                secpCount += 1

        withpadding = b''.join(msgs)
        if self.encrypt:
            withpadding = self.cipher.decrypt(withpadding, chello.getNonce())

        # Remove padding
        if withpadding[0:1] == b'\xff':
            return withpadding[1:], True

        offset = 0
        paddingBytes = 0
        while withpadding[offset:offset + 1] == b'\x00':
            paddingBytes += 254
            offset += 1
        paddingBytes += int.from_bytes(withpadding[offset:offset + 1], 'big')

        return withpadding[paddingBytes:], False

    def recv(self):
        socket, address = self.tlsServer.accept()
        record = self.tlsServer.recv(socket)
        if record is None:
            return None
        elif record.getType() == TLS_HANDSHAKE_RECORD_TYPE and \
                record.getHandshakeType() == HANDSHAKE_TYPE_CLIENT_HELLO:

            byteArray, expecting_more = self.__covertMessage__(record)
            return socket, byteArray

    # def recv(self):
    #     socket, address = self.tlsServer.accept()
    #     expecting_more = True
    #     msgs = []
    #     while expecting_more:
    #         record = self.tlsServer.recv(socket)
    #         if record is None:
    #             print("Received None")
    #             return None
    #         elif record.getType() == TLS_HANDSHAKE_RECORD_TYPE and \
    #                 record.getHandshakeType() == HANDSHAKE_TYPE_CLIENT_HELLO:
    #
    #             byteArray, expecting_more = self.__covertMessage__(record)
    #             msgs.append(byteArray)
    #
    #     return socket, b''.join(msgs)

    def recvfail(self):
        expecting_more = True
        msgs = []
        while expecting_more:
            socket, address = self.tlsServer.accept()
            record = self.tlsServer.recv(socket)
            if record is None:
                return None
            elif record.getType() == TLS_HANDSHAKE_RECORD_TYPE and \
                    record.getHandshakeType() == HANDSHAKE_TYPE_CLIENT_HELLO:

                byteArray, expecting_more = self.__covertMessage__(record)
                msgs.append(byteArray)
                self.tlsServer.handshakeFailure(socket)

        return b''.join(msgs)


def rawOutput(interface, cs):
    ethertype = b'\x08\x00'
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    rawSocket.bind((interface, 0))
    count = 0
    while True:
        data = cs.recvfail()
        count += 1
        print(f"\rCount: {count}", end="")
        frame = b'\x00\x00\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00' + ethertype + data
        rawSocket.send(frame)



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='TLS 1.3 Covert Channel')
    parser.add_argument('--encrypt', action='store_true', help='Enable encryption')
    # parser.add_argument('--key', action='store_true', help='Use one public key as an actual TLS key') #TODO: implement this
    parser.add_argument('-b', '--bind', help='The server IP or domain.')
    parser.add_argument('-p', '--port', help='The server port.')
    args = parser.parse_args()

    if args.bind is None or args.port is None:
        print("Usage: python3 CovertServer.py -b <bind to IP/Domain> -p <port> [--encrypt]")
        exit(1)

    cs = CovertServer(args.bind, args.port, validKey=False, encrypt=args.encrypt)
    rawOutput("lo", cs)
