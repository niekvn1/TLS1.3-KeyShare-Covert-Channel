from TLSValues import TLS_ALERT_RECORD_TYPE, ALERT_LEVEL_FATAL, \
    ALERT_DESC_HANDSHAKE_FAILURE, TLS_VERSION_1_1
from Record import Record

class Alert(Record):
    def init(self, version, alertLevel, alertDescription):
        self.alertLevel = alertLevel
        self.alertDescription = alertDescription
        Record.init(self, TLS_ALERT_RECORD_TYPE, version)

    def parse(self, parse=None):
        thisPart = Record.parse(self, parse)
        self.alertLevel = int.from_bytes(thisPart[0:1], 'big')
        self.alertDescription = int.from_bytes(thisPart[1:2], 'big')


    def calcLength(self):
        """
        Alert Level: 1
        Alert Description: 1
        --------------------- +
        2
        """
        return Record.calcLength(self) + 2

    def toByteArray(self):
        array = Record.toByteArray(self)
        array[0:1] = self.alertLevel.to_bytes(1, 'big')
        array[1:2] = self.alertDescription.to_bytes(1, 'big')
        return array.complete()

    def getAlertLevel(self):
        return self.alertLevel

    def getAlertDescription(self):
        return self.alertDescription


class HandshakeFailure(Alert):
    def init(self):
        Alert.init(self, TLS_VERSION_1_1, ALERT_LEVEL_FATAL, ALERT_DESC_HANDSHAKE_FAILURE)
