class RawField:
    def __init__(self, c, t, n):
        self.classId = c
        self.typeId = t
        self.name = n
        return

class Field(RawField):
    def __init__(self, c, t, n, af):
        RawField.__init__(self, c, t, n)
        self.accessFlags = af
        return

    def fromRawField(rf, af):
        return Field(rf.classId, rf.typeId, rf.name, af)
