class RawMethod:
    def __init__(self, c, p, n):
        self.classId = c
        self.proto = p
        self.name = n
        return

class Method(RawMethod):
    def __init__(self, c, p, n, af, cd):
        RawMethod.__init__(self, c, p, n)
        self.accessFlags = af
        self.code = cd
        return

    def fromRawMethod(rm, af, cd):
        return Method(rm.classId, rm.proto, rm.name, af, cd)

    def __parseAccessFlags(self):
        res = []
        warnings = []
        if(self.accessFlags & 0x01 == 0x01):
            res.append('public')
        if(self.accessFlags & 0x02 == 0x02):
            res.append('private')
        if(self.accessFlags & 0x04 == 0x04):
            res.append('protected')
        if(self.accessFlags & 0x08 == 0x08):
            res.append('static')
        if(self.accessFlags & 0x10 == 0x10):
            res.append('final')
        if(self.accessFlags & 0x20 == 0x20):
            res.append('synchronized')
        if(self.accessFlags & 0x40 == 0x40):
            res.append('bridge')
        if(self.accessFlags & 0x80 == 0x80):
            warnings.append('INFO: the method has a declared compiler directive (last argument should be treated as a "rest" argument)')
        if(self.accessFlags & 0x100 == 0x100):
            res.append('native')
        if(self.accessFlags & 0x200 == 0x200):
            warnings.append('WARNING: the method has an invalid interface attribute')
        if(self.accessFlags & 0x400 == 0x400):
            res.append('abstract')
        if(self.accessFlags & 0x800 == 0x800):
            res.append('strictfp')
        if(self.accessFlags & 0x1000 == 0x1000):
            res.append('synthetic')
        if(self.accessFlags & 0x2000 == 0x2000):
            warnings.append('WARNING: the method has an invalid annotation attribute')
        if(self.accessFlags & 0x4000 == 0x4000):
            warnings.append('WARNING: the method has an invalid enum attribute')
        if(self.accessFlags & 0x10000 == 0x10000):
            res.append('constructor')
        if(self.accessFlags & 0x20000 == 0x20000):
            res.append('declared_synchronized')
        if(self.accessFlags & 0xc8000 != 0x00):
            warnings.append('WARNING: the class has unused flags set')
        return [warnings, res]

    def __str__(self):
        af = self.__parseAccessFlags()
        res = '\n'.join(af[0])
        flags = 0x00
        warnings = []
        try:
            methodName = self.name.decode(self.ENCODING)
            res += '\n.method ' + ' '.join(af[1])
            res += ' ' + methodName + '('
        except(Exception):
            res += 'WARNING: failed to decode method name. Leaving it raw.'
            res += '\n.method ' + ' '.join(af[1])
            res +=  ' ' + str(self.name) + '('
        for parameter in self.proto.parameters:
            try:
                res += parameter.decode(self.ENCODING) + ' '
            except(Exception):
                flags += 0x01
                res += str(parameter) + ' '
        if(len(self.proto.parameters) > 0):
            res = res[:-1]
        try:
            res += ') returns ' + self.proto.returnType.decode(self.ENCODING)
        except(Exception):
            flags += 0x02
            res += ') returns ' + str(self.proto.returnType)
        if(flags & 0x01 == 0x01):
            warnings.append('WARNING: failed to decode some parameters. They were left raw.')
        if(flags & 0x02 == 0x02):
            warnings.append('WARNING: failed to decode some prototypes. They were left raw.')
        return '\n'.join(warnings) + '\n' + res
