from ByteArray import ByteArray

class Frame:
    def __init__(self, *args, **kwargs):
        if "parse" not in kwargs:
            self.init(*args, **kwargs)
            self.length = self.calcLength()
        else:
            self.length = len(kwargs["parse"])
            self.parse(*args, **kwargs)

    def init(self):
        return

    def parse(self):
        return

    def calcLength(self):
        return 0

    def toByteArray(self):
        return ByteArray(self.length)
