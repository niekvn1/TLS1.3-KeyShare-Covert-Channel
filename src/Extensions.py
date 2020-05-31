from Frame import Frame
from TLSValues import EXTENSION_TYPE_KEY_SHARE, EXTENSION_TYPE_SERVER_NAME, \
    EXTENSION_TYPE_SESSION_TICKET, EXTENSION_TYPE_ENCRYPT_THEN_MAC, \
    EXTENSION_TYPE_SUPPORTED_GROUPS, EXTENSION_TYPE_SUPPORTED_VERSIONS, \
    EXTENSION_TYPE_SIGNATURE_ALGORITHMS, EXTENSION_TYPE_EXTENDED_MASTER_SECRET, \
    EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, EXTENSION_TYPE_SUPPORTED_POINT_FORMATS, \
    HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_SERVER_HELLO
from Utils import printBytes

def extensionsParser(thisPart, helloType):
    maxx = len(thisPart)
    offset = 2
    type = -1
    length = -1
    extensions = {}
    while offset < maxx:
        type = int.from_bytes(thisPart[offset:offset + 2], 'big')
        length = int.from_bytes(thisPart[offset + 2:offset + 4], 'big')
        data = thisPart[offset:offset + 4 + length]
        offset += 4 + length
        # print(format(type, "02x"), length)
        if type == EXTENSION_TYPE_SERVER_NAME:
            extensions[type] = ServerName(parse=data)
        elif type == EXTENSION_TYPE_SUPPORTED_POINT_FORMATS:
            extensions[type] = SupportedPointFormats(parse=data)
        elif type == EXTENSION_TYPE_SUPPORTED_GROUPS:
            extensions[type] = SupportedGroups(parse=data)
        elif type == EXTENSION_TYPE_SESSION_TICKET:
            extensions[type] = SessionTicket(parse=data)
        elif type == EXTENSION_TYPE_ENCRYPT_THEN_MAC:
            extensions[type] = EncryptionThenMac(parse=data)
        elif type == EXTENSION_TYPE_EXTENDED_MASTER_SECRET:
            extensions[type] = ExtendedMasterSecret(parse=data)
        elif type == EXTENSION_TYPE_SIGNATURE_ALGORITHMS:
            extensions[type] = SignatureAlgorithms(parse=data)
        elif type == EXTENSION_TYPE_SUPPORTED_VERSIONS:
            extensions[type] = SupportedVersions(helloType, parse=data)
        elif type == EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES:
            extensions[type] = PSKKeyExchangeModes(parse=data)
        elif type == EXTENSION_TYPE_KEY_SHARE:
            extensions[type] = KeyShare(helloType, parse=data)
        else:
            print("Error: Unknown Extension")

    return extensions


class Extension(Frame):
    def init(self, extensionType):
        self.type = extensionType

    def parse(self, parse=None, type=None):
        self.type = type

    def calcLength(self):
        """
        Extension Type: 2
        Extension Length: 2
        --------------------- +
        4
        """
        return 4

    def len(self):
        return self.length

    def toByteArray(self):
        array = Frame.toByteArray(self)
        array[0:2] = self.type.to_bytes(2, 'big')
        array[2:4] = (len(array) - 4).to_bytes(2, 'big')
        return array[4:]


class ServerName(Extension):
    def init(self, servername):
        self.servername = servername
        Extension.init(self, EXTENSION_TYPE_SERVER_NAME)

    def parse(self, parse=None):
        self.servername = parse[9:].decode('ASCII')
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_SERVER_NAME)

    def calcLength(self):
        """
        List Length: 2
        List Entry Type: 1
        Hostname Length: 2
        Hostname: X
        --------------------- +
        5 + X
        """
        return Extension.calcLength(self) + 5 + len(self.servername)

    def toByteArray(self):
        array = Extension.toByteArray(self)
        array[0:2] = (len(array) - 2).to_bytes(2, 'big')
        array[2:3] = (0x00).to_bytes(1, 'big')
        array[3:5] = (len(array) - 5).to_bytes(2, 'big')
        array[5:5 + len(self.servername)] = bytearray(self.servername, "ASCII")
        return array.complete()


class SupportedPointFormats(Extension):
    def init(self, supportedPointFormats):
        self.supportedPointFormats = supportedPointFormats
        Extension.init(self, EXTENSION_TYPE_SUPPORTED_POINT_FORMATS)

    def parse(self, parse=None):
        length = int.from_bytes(parse[4:5], 'big')
        self.supportedPointFormats = []
        for offset in range(5, 5 + length, 1):
            self.supportedPointFormats.append(int.from_bytes(parse[offset:offset + 1], 'big'))
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_SUPPORTED_POINT_FORMATS)

    def calcLength(self):
        """
        List Length: 1
        Formats: X
        -------------------- +
        1 + X
        """
        return Extension.calcLength(self) + 1 + len(self.supportedPointFormats)

    def toByteArray(self):
        array = Extension.toByteArray(self)
        array[0:1] = (len(array) - 1).to_bytes(1, 'big')

        offset = 1
        for format in self.supportedPointFormats:
            array[offset:offset + 1] = format.to_bytes(1, 'big')
            offset += 1

        return array.complete()


class SupportedGroups(Extension):
    def init(self, supportedGroups):
        self.supportedGroups = supportedGroups
        Extension.init(self, EXTENSION_TYPE_SUPPORTED_GROUPS)

    def parse(self, parse=None):
        length = int.from_bytes(parse[4:6], 'big')
        self.supportedGroups = []
        for offset in range(6, 6 + length, 2):
            self.supportedGroups.append(int.from_bytes(parse[offset:offset + 2], 'big'))
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_SUPPORTED_GROUPS)

    def calcLength(self):
        """
        List Length: 2
        Groups: X
        --------------------- +
        2 + x
        """
        return Extension.calcLength(self) + 2 + len(self.supportedGroups) * 2

    def toByteArray(self):
        array = Extension.toByteArray(self)
        array[0:2] = (len(array) - 2).to_bytes(2, 'big')

        offset = 2
        for group in self.supportedGroups:
            array[offset:offset + 2] = group.to_bytes(2, 'big')
            offset += 2

        return array.complete()


class SessionTicket(Extension):
    def init(self):
        Extension.init(self, EXTENSION_TYPE_SESSION_TICKET)

    def parse(self, parse=None):
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_SESSION_TICKET)

    def calcLength(self):
        """
        Ticket: X
        -------------------- +
        X (Zero Length means ask for ticket from server)
        """
        # TODO: Check if session ticket is useful
        return Extension.calcLength(self) + 0

    def toByteArray(self):
        array = Extension.toByteArray(self)
        return array.complete()


class EncryptionThenMac(Extension):
    def init(self):
        Extension.init(self, EXTENSION_TYPE_ENCRYPT_THEN_MAC)

    def parse(self, parse=None):
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_ENCRYPT_THEN_MAC)

    def calcLength(self):
        """
        No Data: 0
        -------------------- +
        0
        """
        return Extension.calcLength(self) + 0

    def toByteArray(self):
        array = Extension.toByteArray(self)
        return array.complete()


class ExtendedMasterSecret(Extension):
    def init(self):
        Extension.init(self, EXTENSION_TYPE_EXTENDED_MASTER_SECRET)

    def parse(self, parse=None):
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_EXTENDED_MASTER_SECRET)

    def calcLength(self):
        """
        No Data: 0
        -------------------- +
        0
        """
        return Extension.calcLength(self) + 0

    def toByteArray(self):
        array = Extension.toByteArray(self)
        return array.complete()


class SignatureAlgorithms(Extension):
    def init(self, signatureAlgorithms):
        self.signatureAlgorithms = signatureAlgorithms
        Extension.init(self, EXTENSION_TYPE_SIGNATURE_ALGORITHMS)

    def parse(self, parse=None):
        length = int.from_bytes(parse[4:6], 'big')
        self.signatureAlgorithms = []
        for offset in range(6, 6 + length, 2):
            self.signatureAlgorithms.append(int.from_bytes(parse[offset:offset + 2], 'big'))
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_SIGNATURE_ALGORITHMS)

    def calcLength(self):
        """
        Algorithm List Length: 2
        Algorithm List: X
        -------------------- +
        2 + X
        """
        return Extension.calcLength(self) + 2 + len(self.signatureAlgorithms) * 2

    def toByteArray(self):
        array = Extension.toByteArray(self)
        array[0:2] = (len(array) - 2).to_bytes(2, 'big')

        offset = 2
        for algorithm in self.signatureAlgorithms:
            array[offset:offset + 2] = algorithm.to_bytes(2, 'big')
            offset += 2

        return array.complete()


class SupportedVersions(Extension):
    def init(self, helloType, supportedVersions):
        self.supportedVersions = supportedVersions
        self.helloType = helloType
        Extension.init(self, EXTENSION_TYPE_SUPPORTED_VERSIONS)

    def parse(self, helloType, parse=None):
        self.helloType = helloType
        self.supportedVersions = []

        if self.helloType == HANDSHAKE_TYPE_CLIENT_HELLO:
            length = int.from_bytes(parse[4:5], 'big')
            for offset in range(5, 5 + length, 2):
                self.supportedVersions.append(int.from_bytes(parse[offset:offset + 2], 'big'))
        elif self.helloType == HANDSHAKE_TYPE_SERVER_HELLO:
            length = int.from_bytes(parse[2:4], 'big')
            for offset in range(4, 4 + length, 2):
                self.supportedVersions.append(int.from_bytes(parse[offset:offset + 2], 'big'))

        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_SUPPORTED_VERSIONS)

    def calcLength(self):
        """
        [Version List Length: 1]
        Version List: X
        -------------------- +
        1 + X
        """
        if self.helloType == HANDSHAKE_TYPE_CLIENT_HELLO:
            return Extension.calcLength(self) + 1 + len(self.supportedVersions) * 2
        elif self.helloType == HANDSHAKE_TYPE_SERVER_HELLO:
            return Extension.calcLength(self) + len(self.supportedVersions) * 2
        else:
            print("Error: Unknown Hello Type")

    def toByteArray(self):
        array = Extension.toByteArray(self)
        if self.helloType == HANDSHAKE_TYPE_CLIENT_HELLO:
            array[0:1] = (len(array) - 1).to_bytes(1, 'big')
            offset = 1
        elif self.helloType == HANDSHAKE_TYPE_SERVER_HELLO:
            offset = 0
        else:
            print("Error: Unknown Hello Type")

        for version in self.supportedVersions:
            array[offset:offset + 2] = version.to_bytes(2, 'big')
            offset += 2

        return array.complete()


class PSKKeyExchangeModes(Extension):
    def init(self, supportedPSKKeyExchangeModes):
        self.supportedPSKKeyExchangeModes = supportedPSKKeyExchangeModes
        Extension.init(self, EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES)

    def parse(self, parse=None):
        length = int.from_bytes(parse[4:5], 'big')
        self.supportedPSKKeyExchangeModes = []
        for offset in range(5, 5 + length, 1):
            self.supportedPSKKeyExchangeModes.append(int.from_bytes(parse[offset:offset + 1], 'big'))
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES)

    def calcLength(self):
        """
        Mode List Length: 1
        Mode List: X
        -------------------- +
        1 + X
        """
        return Extension.calcLength(self) + 1 + len(self.supportedPSKKeyExchangeModes)

    def toByteArray(self):
        array = Extension.toByteArray(self)
        array[0:1] = (len(array) - 1).to_bytes(1, 'big')

        offset = 1
        for mode in self.supportedPSKKeyExchangeModes:
            array[offset:offset + 1] = mode.to_bytes(1, 'big')
            offset += 1

        return array.complete()

class KeyShare(Extension):
    def init(self, helloType, keys):
        self.helloType = helloType
        self.keyShareGroups = keys.keys()
        self.groupKeyLengths = [len(key) for key in keys.values()]
        self.keys = keys.values()
        Extension.init(self, EXTENSION_TYPE_KEY_SHARE)

    def parse(self, helloType, parse=None):
        self.helloType = helloType
        self.keyShareGroups = []
        self.groupKeyLengths = {}
        self.keys = []

        maxx = len(parse)
        if self.helloType == HANDSHAKE_TYPE_CLIENT_HELLO:
            offset = 6
        elif self.helloType == HANDSHAKE_TYPE_SERVER_HELLO:
            offset = 4
        else:
            print("Error: Unknown Hello Type")

        while offset < maxx:
            type = int.from_bytes(parse[offset:offset + 2], 'big')
            keyLength = int.from_bytes(parse[offset + 2:offset + 4], 'big')
            key = parse[offset + 4:offset + 4 + keyLength]
            offset += 4 + keyLength
            self.keyShareGroups.append(type)
            self.groupKeyLengths[type] = keyLength
            self.keys.append(key)
        Extension.parse(self, parse=parse, type=EXTENSION_TYPE_KEY_SHARE)

    def calcLength(self):
        """
        [Key List Length: 2]
        Key List: X     (2 bytes type + 2 bytes length + Y bytes key)
        -------------------- +
        2 + X
        """
        length = 0
        for keyLength in self.groupKeyLengths:
            length += 4 + keyLength

        if self.helloType == HANDSHAKE_TYPE_CLIENT_HELLO:
            return Extension.calcLength(self) + 2 + length
        elif self.helloType == HANDSHAKE_TYPE_SERVER_HELLO:
            return Extension.calcLength(self) + length
        else:
            print("Error: Unknown Hello Type")

    def toByteArray(self):
        array = Extension.toByteArray(self)
        if self.helloType == HANDSHAKE_TYPE_CLIENT_HELLO:
            array[0:2] = (len(array) - 2).to_bytes(2, 'big')
            offset = 2
        elif self.helloType == HANDSHAKE_TYPE_SERVER_HELLO:
            offset = 0
        else:
            print("Error: Unknown Hello Type")

        for group, key, l in zip(self.keyShareGroups, self.keys, self.groupKeyLengths):
            array[offset:offset + 2] = group.to_bytes(2, 'big')
            array[offset + 2:offset + 4] = l.to_bytes(2, 'big')
            array[offset + 4:offset + 4 + l] = key
            offset += 4 + l

        return array.complete()
