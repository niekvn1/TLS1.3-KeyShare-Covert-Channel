class ByteArray:
    def __init__(self, *args, **kwargs):
        l = len(args)
        if l == 1:
            self.__lengthinit__(*args, **kwargs)
        elif l == 2:
            self.__sliceinit__(*args, **kwargs)

    def __lengthinit__(self, length):
        self.array = bytearray(length)
        self.start, self.stop, self.step = (0, len(self.array), 1)

    def __sliceinit__(self, array, slice):
        self.array = array
        self.start, self.stop, self.step = slice.indices(len(self.array))

    def __iter__(self):
        return self.array.__iter__()

    def __next__(self):
        return self.array.__next__()

    def __str__(self):
        return self.array[self.start:self.stop].__str__()

    def __len__(self):
        return self.stop - self.start

    def __getitem__(self, index):
        if (type(index) is slice):
            start, stop, step = index.indices(len(self))
            s = slice(self.start + start, self.start + stop, step)
            return ByteArray(self.array, s)
        else:
            return self.array.__getitem__(index)

    def __setitem__(self, index, value):
        if (type(index) is slice):
            start, stop, step = index.indices(len(self))
            s = slice(self.start + start, self.start + stop, step)
            self.array.__setitem__(s, value)
        else:
            self.array.__setitem__(self.start + index, value)

    def complete(self):
        return self.array
