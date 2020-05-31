import socket
from ClientHello import ClientHello
from ServerHello import ServerHello
from Alert import HandshakeFailure
from TLSValues import *
from Utils import printBytes, loadPublicKeys


class TLSServer:
    def __init__(self, servername, port, key):
        self.servername = servername
        self.port = port
        self.key = key
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.servername, self.port))
        self.s.listen(1)

    def accept(self):
        return self.s.accept()

    def recv(self, socket):
        msg = socket.recv(4092)
        if msg == b'':
            socket.close()
            return None

        if int.from_bytes(msg[0:1], 'big') != TLS_HANDSHAKE_RECORD_TYPE:
            return None

        lengthTotal = int.from_bytes(msg[3:5], 'big') + 5
        length = len(msg)
        msgs = [msg]
        while length < lengthTotal:
            msg = socket.recv(4092)
            if msg == b'':
                socket.close()
                return None

            msgs.append(msg)
            length += len(msg)

        msg = b''.join(msgs)

        if int.from_bytes(msg[0:1], 'big') == TLS_HANDSHAKE_RECORD_TYPE and \
                int.from_bytes(msg[5:6], 'big') == HANDSHAKE_TYPE_CLIENT_HELLO:
            return ClientHello(parse=msg)

    def handshakeFailure(self, socket):
        hfailure = HandshakeFailure()
        socket.send(hfailure.toByteArray())
        socket.close()

    def hello(self, socket, chello):
        shello = ServerHello(chello, [self.key])
        socket.send(shello.toByteArray())

    def close(self):
        self.s.close()


if __name__ == "__main__":
    key = loadPublicKey(SUPPORTED_GROUP_X25519, "client_crypto/x25519public.key.pem")
    s = Server("localhost", 44330, key)
