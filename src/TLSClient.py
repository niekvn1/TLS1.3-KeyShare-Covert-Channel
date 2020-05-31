import socket
from ClientHello import ClientHello
from ServerHello import ServerHello
from Alert import Alert
from TLSValues import SUPPORTED_GROUP_X25519, SUPPORTED_GROUP_X448, \
    TLS_ALERT_RECORD_TYPE
from Utils import printBytes, loadPublicKeys


class TLSClient:
    def __init__(self, servername, port):
        self.servername = servername
        self.port = port

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.servername, self.port))

    def send(self, bytes):
        self.s.send(bytes)

    def recv(self):
        msg = self.s.recv(4092)
        if msg == b'':
            self.close()
            return None

        if int.from_bytes(msg[0:1], 'big') == TLS_ALERT_RECORD_TYPE:
            return Alert(parse=msg)

    def close(self):
        self.s.close()

    def hello(self, keys, sessionID, nonce=None):
        chello = ClientHello(self.servername, keys, sessionID=sessionID, nonce=nonce)
        self.send(chello.toByteArray())

    def fileno(self):
        return self.s.fileno()


if __name__ == "__main__":
    keyfiles = [
                (SUPPORTED_GROUP_X25519, "client_crypto/x25519public.key.pem"),
                (SUPPORTED_GROUP_X448, "client_crypto/x448public.key.pem")
               ]
    keys = loadPublicKeys(keyfiles)
    c = TLSClient("www.nice.prac.os3.nl", 44330)
    c.connect()
    response = c.hello(keys)
    c.close()
    printBytes(response)
