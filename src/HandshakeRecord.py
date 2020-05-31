from TLSValues import TLS_HANDSHAKE_RECORD_TYPE
from Record import Record
from Frame import Frame
from os import urandom

class HandshakeRecord(Record):
    def init(self, version, handshakeType):
        self.handshakeType = handshakeType
        Record.init(self, TLS_HANDSHAKE_RECORD_TYPE, version)

    def parse(self, parse=None):
        thisPart = Record.parse(self, parse)
        self.handshakeType = int.from_bytes(thisPart[0:1], 'big')
        dataLength = int.from_bytes(thisPart[1:4], 'big')
        return thisPart[4:]


    def calcLength(self):
        """
        Handshake Type: 1
        ClientHelloLength: 3
        --------------------- +
        4
        """
        return Record.calcLength(self) + 4

    def toByteArray(self):
        array = Record.toByteArray(self)
        array[0:1] = self.handshakeType.to_bytes(1, 'big')
        array[1:4] = (len(array) - 4).to_bytes(3, 'big')
        return array[4:]

    def getHandshakeType(self):
        return self.handshakeType


class Field(Frame):
    def len(self):
        return self.length


class VersionField(Field):
    def init(self, version):
        self.version = version

    def parse(self, parse=None):
        self.version = int.from_bytes(parse, 'big')

    def calcLength(self):
        """
        Version: 2
        """
        return 2

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:2] = self.version.to_bytes(2, 'big')
        return array.complete()


class NonceField(Field):
    def init(self, nonce=None):
        if nonce is None:
            self.nonce = urandom(32)
        else:
            self.nonce = nonce

    def parse(self, parse=None):
        self.nonce = parse

    def calcLength(self):
        """
        32 Bytes Nonce
        """
        return 32

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:32] = self.nonce
        return array.complete()


class SessionIDField(Field):
    def init(self, id=None):
        if id is None:
            self.id = urandom(32)
        else:
            self.id = id

    def parse(self, parse=None):
        self.id = parse[1:]

    def calcLength(self):
        """
        1 Byte Session ID Length
        32 Bytes Session ID
        """
        return 33

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:1] = (32).to_bytes(1, 'big')
        array[1:33] = self.id
        return array.complete()


class CipherSuitesField(Field):
    def init(self, cipherSuites):
        self.cipherSuites = cipherSuites

    def parse(self, parse=None):
        self.cipherSuites = []
        for offset in range(2, len(parse), 2):
            self.cipherSuites.append(int.from_bytes(parse[offset:offset + 2], 'big'))

    def calcLength(self):
        """
        Length: 2
        Cipher Suites: X
        """
        return 2 + len(self.cipherSuites) * 2

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:2] = (len(self.cipherSuites) * 2).to_bytes(2, 'big')
        offset = 2
        for cipher in self.cipherSuites:
            array[offset:offset + 2] = cipher.to_bytes(2, 'big')
            offset += 2
        return array.complete()


class SelectedCipherSuiteField(Field):
    def init(self, clientCipherSuites, cipherSuites):
        self.clientCipherSuites = clientCipherSuites
        self.cipherSuites = cipherSuites
        self.cipherSuite = self.chooseSuite()

    def parse(self, parse=None):
        self.cipherSuite = int.from_bytes(parse[0:2], 'big')

    def calcLength(self):
        """
        Cipher Suite: 2
        """
        return 2

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:2] = self.cipherSuite.to_bytes(2, 'big')
        return array.complete()

    def chooseSuite(self):
        commenSuites = []
        for suite in self.clientCipherSuites:
            if suite in self.cipherSuites:
                commenSuites.append(suite)

        if len(commenSuites) == 0:
            # TODO: Act on this
            print("Error: No commen cipher suite")
        else:
            return commenSuites[0]


class CompressionMethodField(Field):
    def init(self, method):
        self.method = method
        self.methodLength = 1

    def parse(self, parse=None):
        self.methodLength = int.from_bytes(parse[0:1], 'big')
        self.method = int.from_bytes(parse[1:self.methodLength], 'big')

    def calcLength(self):
        """
        0x0100: 2
        """
        return 2

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:1] = self.methodLength.to_bytes(1, 'big')
        array[1:1 + self.methodLength] = self.method.to_bytes(self.methodLength, 'big')
        return array.complete()

class SelectedCompressionMethodField(Field):
    def init(self, method):
        self.method = method

    def parse(self, parse=None):
        self.method = int.from_bytes(parse[0:1], 'big')

    def calcLength(self):
        """
        0x00: 1
        """
        return 1

    def toByteArray(self):
        array = Field.toByteArray(self)
        array[0:1] = self.method.to_bytes(1, 'big')
        return array.complete()
