class Class:
    def __init__(self, dex, c, af, sc, i, sf, a, cd, sv):
        self.dex = dex
        self.classId = c
        self.accessFlags = af
        self.superclass = sc
        self.interfaces = i
        self.sourceFile = sf
        self.annotations = a
        self.staticFields = cd[0]
        self.instanceFields = cd[1]
        self.directMethods = cd[2]
        self.virtualMethods = cd[3]
        self.staticValues = sv
        return

    def __parseAccessFlags(self):
        res = []
        warnings = []
        if(self.accessFlags & 0x01 == 0x01):
            res.append('public')
        if(self.accessFlags & 0x02 == 0x02):
            warnings.append('WARNING: the class has an invalid private attribute')
        if(self.accessFlags & 0x04 == 0x04):
            warnings.append('WARNING: the class has an invalid protected attribute')
        if(self.accessFlags & 0x08 == 0x08):
            warnings.append('WARNING: the class has an invalid static attribute')
        if(self.accessFlags & 0x10 == 0x10):
            res.append('final')
        if(self.accessFlags & 0x20 == 0x20):
            warnings.append('WARNING: the class has an invalid synchronized attribute')
        if(self.accessFlags & 0x40 == 0x40):
            warnings.append('WARNING: the class has an invalid volatile or bridge attribute')
        if(self.accessFlags & 0x80 == 0x80):
            warnings.append('WARNING: the class has an invalid transient attribute or compiler argument directive')
        if(self.accessFlags & 0x100 == 0x100):
            warnings.append('WARNING: the class has an invalid native attribute')
        if(self.accessFlags & 0x200 == 0x200):
            res.append('interface')
        if(self.accessFlags & 0x400 == 0x400):
            res.append('abstract')
        if(self.accessFlags & 0x800 == 0x800):
            warnings.append('WARNING: the class has an invalid strictfp attribute')
        if(self.accessFlags & 0x1000 == 0x1000):
            res.append('synthetic')
        if(self.accessFlags & 0x2000 == 0x2000):
            res.append('annotation')
        if(self.accessFlags & 0x4000 == 0x4000):
            res.append('enum')
        if(self.accessFlags & 0x10000 == 0x10000):
            warnings.append('WARNING: the class has an invalid constructor attribute')
        if(self.accessFlags & 0x20000 == 0x20000):
            warnings.append('WARNING: the class has an invalid declared_synchronized attribute')
        if(self.accessFlags & 0xc8000 != 0x00):
            warnings.append('WARNING: the class has unused flags set')
        return [warnings, res]

    def __str__(self):
        af = self.__parseAccessFlags()
        res = '\n'.join(af[0])
        try:
            className = self.classId.decode(Dex.ENCODING)
            res += '\n.class ' + ' '.join(af[1])
            res += ' ' + className + '\n'
        except(Exception):
            res += '\nWARNING: failed to decode class name. Leaving it raw.'
            res += '\n.class ' + ' '.join(af[1])
            res +=  ' ' + str(self.classId) + '\n'
        for method in (self.directMethods + self.virtualMethods):
            res += method.__str__() + '\n'
            if(method.code is not None):
                res += method.code.disassemble()
        return res