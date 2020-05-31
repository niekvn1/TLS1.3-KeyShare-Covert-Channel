from HandshakeRecord import HandshakeRecord, VersionField, NonceField, \
    SessionIDField, SelectedCipherSuiteField, SelectedCompressionMethodField
from TLSValues import HANDSHAKE_TYPE_SERVER_HELLO, TLS_VERSION_1_2, \
    EXTENSION_TYPE_KEY_SHARE, EXTENSION_TYPE_SUPPORTED_VERSIONS, \
    FIELD_TYPE_VERSION, FIELD_TYPE_NONCE, FIELD_TYPE_SESSION_ID, \
    FIELD_TYPE_SELECTED_CIPHER_SUITE, FIELD_TYPE_SELECTED_COMPRESSION_METHOD, \
    SUPPORTED_GROUPS, CIPHER_SUITES, KEY_LENGTHS, TLS_VERSIONS
from Extensions import SupportedVersions, KeyShare, extensionsParser

class ServerHello(HandshakeRecord):
    def init(self, clientHello, keys,
                 cipherSuites=CIPHER_SUITES,
                 supportedGroups=SUPPORTED_GROUPS,
                 supportedVersions=TLS_VERSIONS,
                 ):
        self.fields = {
            FIELD_TYPE_VERSION: VersionField(TLS_VERSION_1_2),
            FIELD_TYPE_NONCE: NonceField(),
            FIELD_TYPE_SESSION_ID: SessionIDField(clientHello.getSessionID()),
            FIELD_TYPE_SELECTED_CIPHER_SUITE: SelectedCipherSuiteField(clientHello.getCipherSuites(), cipherSuites),
            FIELD_TYPE_SELECTED_COMPRESSION_METHOD: SelectedCompressionMethodField(0x00)
        }
        self.extensions = {
            EXTENSION_TYPE_SUPPORTED_VERSIONS: SupportedVersions(HANDSHAKE_TYPE_SERVER_HELLO, supportedVersions),
            EXTENSION_TYPE_KEY_SHARE: KeyShare(HANDSHAKE_TYPE_SERVER_HELLO, keys)
        }

        HandshakeRecord.init(self, TLS_VERSION_1_2, HANDSHAKE_TYPE_SERVER_HELLO)

    def parse(self, parse=None):
        thisPart = HandshakeRecord.parse(self, parse)

        vf = VersionField(parse=thisPart[0:2])
        nf = NonceField(parse=thisPart[2:34])

        sessionIDLength = 1 + int.from_bytes(thisPart[34:35], 'big')
        sid = SessionIDField(parse=thisPart[34:34 + sessionIDLength])
        offset = 34 + sessionIDLength

        scf = SelectedCipherSuiteField(parse=thisPart[offset:offset + 2])
        offset += 2

        cmf = SelectedCompressionMethodField(parse=thisPart[offset:offset + 1])
        offset += 1

        self.fields = {
            FIELD_TYPE_VERSION: vf,
            FIELD_TYPE_NONCE: nf,
            FIELD_TYPE_SESSION_ID: sid,
            FIELD_TYPE_SELECTED_CIPHER_SUITE: scf,
            FIELD_TYPE_SELECTED_COMPRESSION_METHOD: cmf
        }

        extensionsLength = 2 + int.from_bytes(thisPart[offset:offset + 2], 'big')
        self.extensions = extensionsParser(thisPart[offset:offset + extensionsLength], HANDSHAKE_TYPE_SERVER_HELLO)

    def calcLength(self):
        """
        Fields: X
        Extensions Length: 2
        Extensions: Y
        -------------------------------- +
        X + 2 + Y
        """
        return HandshakeRecord.calcLength(self) + 2 \
            + sum([field.len() for field in self.fields.values()]) \
            + sum([ext.len() for ext in self.extensions.values()])

    def toByteArray(self):
        array = HandshakeRecord.toByteArray(self)
        offset = 0
        for field in self.fields.values():
            array[offset:offset + field.len()] = field.toByteArray()
            offset += field.len()

        array[offset:offset + 2] = (len(array) - (offset + 2)).to_bytes(2, 'big')
        offset += 2
        for ext in self.extensions.values():
            array[offset:offset + ext.len()] = ext.toByteArray()
            offset += ext.len()

        return array.complete()

    def getVersion(self):
        return self.fields[FIELD_TYPE_VERSION].version

    def getNonce(self):
        return self.fields[FIELD_TYPE_NONCE].nonce

    def getSessionID(self):
        return self.fields[FIELD_TYPE_SESSION_ID].id

    def getCipherSuites(self):
        return self.fields[FIELD_TYPE_SELECTED_CIPHER_SUITE].cipherSuite

    def getCompressionMethod(self):
        return self.fields[FIELD_TYPE_SELECTED_COMPRESSION_METHOD].method

    def getSupportedVersions(self):
        return self.extensions[EXTENSION_TYPE_SUPPORTED_VERSIONS].supportedVersions

    def getKeys(self):
        return self.extensions[EXTENSION_TYPE_KEY_SHARE].keys

    def getKeyGroups(self):
        return self.extensions[EXTENSION_TYPE_KEY_SHARE].keyShareGroups

    def getKeyLengths(self):
        return self.extensions[EXTENSION_TYPE_KEY_SHARE].groupKeyLengths
