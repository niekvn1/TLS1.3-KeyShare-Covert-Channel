from HandshakeRecord import HandshakeRecord, VersionField, NonceField, \
    SessionIDField, CipherSuitesField, CompressionMethodField
from Extensions import ServerName, SupportedPointFormats, SupportedGroups, \
    SessionTicket, EncryptionThenMac, ExtendedMasterSecret, SignatureAlgorithms, \
    SupportedVersions, PSKKeyExchangeModes, KeyShare, extensionsParser
from TLSValues import SUPPORTED_GROUPS, CIPHER_SUITES, SUPPORTED_POINT_FORMATS, \
    KEY_LENGTHS, SIGNATURE_ALGORITHMS, TLS_VERSIONS, PSK_KEY_EXHANGE_MODES, \
    TLS_VERSION_1_1, TLS_VERSION_1_2, HANDSHAKE_TYPE_CLIENT_HELLO, \
    EXTENSION_TYPE_KEY_SHARE, EXTENSION_TYPE_SERVER_NAME, \
    EXTENSION_TYPE_SESSION_TICKET, EXTENSION_TYPE_ENCRYPT_THEN_MAC, \
    EXTENSION_TYPE_SUPPORTED_GROUPS, EXTENSION_TYPE_SUPPORTED_VERSIONS, \
    EXTENSION_TYPE_SIGNATURE_ALGORITHMS, EXTENSION_TYPE_EXTENDED_MASTER_SECRET, \
    EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES, EXTENSION_TYPE_SUPPORTED_POINT_FORMATS, \
    FIELD_TYPE_VERSION, FIELD_TYPE_NONCE, FIELD_TYPE_SESSION_ID, \
    FIELD_TYPE_CIPHER_SUITES, FIELD_TYPE_COMPRESSION_METHOD
from Utils import printBytes


class ClientHello(HandshakeRecord):
    def init(self, servername, keys, sessionID=None, nonce=None,
                 cipherSuites=CIPHER_SUITES,
                 supportedPointFormats=SUPPORTED_POINT_FORMATS,
                 supportedGroups=SUPPORTED_GROUPS,
                 signatureAlgorithms=SIGNATURE_ALGORITHMS,
                 supportedVersions=TLS_VERSIONS,
                 supportedPSKKeyExchangeModes=PSK_KEY_EXHANGE_MODES,
                 ):
        self.fields = {
            FIELD_TYPE_VERSION: VersionField(TLS_VERSION_1_2),
            FIELD_TYPE_NONCE: NonceField(nonce=nonce),
            FIELD_TYPE_SESSION_ID: SessionIDField(id=sessionID),
            FIELD_TYPE_CIPHER_SUITES: CipherSuitesField(cipherSuites),
            FIELD_TYPE_COMPRESSION_METHOD: CompressionMethodField(0x00)
        }
        self.extensions = {
            EXTENSION_TYPE_SERVER_NAME: ServerName(servername),
            EXTENSION_TYPE_SUPPORTED_POINT_FORMATS: SupportedPointFormats(supportedPointFormats),
            EXTENSION_TYPE_SUPPORTED_GROUPS: SupportedGroups(supportedGroups),
            EXTENSION_TYPE_SESSION_TICKET: SessionTicket(),
            EXTENSION_TYPE_ENCRYPT_THEN_MAC: EncryptionThenMac(),
            EXTENSION_TYPE_EXTENDED_MASTER_SECRET: ExtendedMasterSecret(),
            EXTENSION_TYPE_SIGNATURE_ALGORITHMS: SignatureAlgorithms(signatureAlgorithms),
            EXTENSION_TYPE_SUPPORTED_VERSIONS: SupportedVersions(HANDSHAKE_TYPE_CLIENT_HELLO, supportedVersions),
            EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES: PSKKeyExchangeModes(supportedPSKKeyExchangeModes),
            EXTENSION_TYPE_KEY_SHARE: KeyShare(HANDSHAKE_TYPE_CLIENT_HELLO, keys)
        }

        HandshakeRecord.init(self, TLS_VERSION_1_1, HANDSHAKE_TYPE_CLIENT_HELLO)

    def parse(self, parse=None):
        thisPart = HandshakeRecord.parse(self, parse)

        vf = VersionField(parse=thisPart[0:2])
        nf = NonceField(parse=thisPart[2:34])

        sessionIDLength = 1 + int.from_bytes(thisPart[34:35], 'big')
        sid = SessionIDField(parse=thisPart[34:34 + sessionIDLength])
        offset = 34 + sessionIDLength

        cipherSuitesLength = 2 + int.from_bytes(thisPart[offset:offset + 2], 'big')
        cf = CipherSuitesField(parse=thisPart[offset:offset + cipherSuitesLength])
        offset += cipherSuitesLength

        compressionMethodLength = 1 + int.from_bytes(thisPart[offset:offset + 1], 'big')
        cmf = CompressionMethodField(parse=thisPart[offset:offset + compressionMethodLength])
        offset += compressionMethodLength

        self.fields = {
            FIELD_TYPE_VERSION: vf,
            FIELD_TYPE_NONCE: nf,
            FIELD_TYPE_SESSION_ID: sid,
            FIELD_TYPE_CIPHER_SUITES: cf,
            FIELD_TYPE_COMPRESSION_METHOD: cmf
        }

        extensionsLength = 2 + int.from_bytes(thisPart[offset:offset + 2], 'big')
        self.extensions = extensionsParser(thisPart[offset:offset + extensionsLength],
                                           HANDSHAKE_TYPE_CLIENT_HELLO)

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
        return self.fields[FIELD_TYPE_CIPHER_SUITES].cipherSuites

    def getCompressionMethod(self):
        return self.fields[FIELD_TYPE_COMPRESSION_METHOD].method

    def getServerName(self):
        return self.extensions[EXTENSION_TYPE_SERVER_NAME].servername

    def getSupportedPointFormats(self):
        return self.extensions[EXTENSION_TYPE_SUPPORTED_POINT_FORMATS].supportedPointFormats

    def getSupportedGroups(self):
        return self.extensions[EXTENSION_TYPE_SUPPORTED_GROUPS].supportedGroups

    def getSessionTicket(self):
        return EXTENSION_TYPE_SESSION_TICKET in self.extensions

    def getEncryptThenMac(self):
        return EXTENSION_TYPE_ENCRYPT_THEN_MAC in self.extensions

    def getExtendedMasterSecret(self):
        return EXTENSION_TYPE_EXTENDED_MASTER_SECRET in self.extensions

    def getSignatureAlgorithms(self):
        return self.extensions[EXTENSION_TYPE_SIGNATURE_ALGORITHMS].signatureAlgorithms

    def getSupportedVersions(self):
        return self.extensions[EXTENSION_TYPE_SUPPORTED_VERSIONS].supportedVersions

    def getPSKKeyExchangeModes(self):
        return self.extensions[EXTENSION_TYPE_PSK_KEY_EXCHANGE_MODES].supportedPSKKeyExchangeModes

    def getKeys(self):
        return self.extensions[EXTENSION_TYPE_KEY_SHARE].keys

    def getKeyGroups(self):
        return self.extensions[EXTENSION_TYPE_KEY_SHARE].keyShareGroups

    def getKeyLengths(self):
        return self.extensions[EXTENSION_TYPE_KEY_SHARE].groupKeyLengths
