from Frame import Frame

class Record(Frame):
    def init(self, type, version):
        self.type = type
        self.version = version

    def parse(self, parse=None):
        self.type = int.from_bytes(parse[0:1], 'big')
        self.version = int.from_bytes(parse[1:3], 'big')
        dataLength = int.from_bytes(parse[3:5], 'big')
        return parse[5:5 + dataLength]

    def calcLength(self):
        """
        Record Type: 1
        TLS Version: 2
        Record Length: 2
        Data: X
        -------------------------------- +
        5 + X
        """
        return 5

    def toByteArray(self):
        array = Frame.toByteArray(self)
        array[0] = self.type
        array[1:3] = self.version.to_bytes(2, 'big')
        array[3:5] = (self.length - 5).to_bytes(2, 'big')
        return array[5:]

    def getType(self):
        return self.type
