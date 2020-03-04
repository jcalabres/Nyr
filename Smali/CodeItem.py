class CodeItem:
    def __init__(self, dex, rs, insS, outS, dbg, insns, tries, handlers):
        self.encoding = dex.ENCODING
        self.intParser = dex.toUint
        self.typeResolver = dex.getType
        self.fieldResolver = dex.getRawField
        self.methodResolver = dex.getRawMethod
        self.stringResolver = dex.getString 
        self.registers = rs
        self.incomingSize = insS
        self.outgoingSize = outS
        self.debugInfo = dbg
        self.insns = insns
        self.tries = tries
        self.handlers = handlers
        return

    def resolveParams(self, param):
        if(param < self.registers - self.incomingSize):
            return 'v' + str(param)
        else:
            return 'p' + str(param - self.registers + self.incomingSize)

    def __getArguments(self, format, bytecode):
        if(format == '00x'):
            return [0]
        elif(format == '10x'):
            if(bytecode[1] != 0x00):
                raise Exception
            return [2]
        elif(format == '12x' or format == '11n'):
            A = bytecode[1] & 0x0f
            B = (bytecode[1] & 0xf0) >> 4
            return [A, B, 2]
        elif(format == '11x' or format == '10t'):
            return [bytecode[1], 2]
        elif(format == '20t'):
            if(bytecode[1] != 0x00):
                raise Exception
            return [self.intParser(bytecode[2 : 4]), 4]
        elif(format == '20bc' or format == '22x' or format == '21t' or format == '21s' or format == '21h' or format == '21c'):
            A = bytecode[1]
            B = self.intParser(bytecode[2 : 4])
            return [A, B, 4]
        elif(format == '23x' or format == '22b'):
            return [bytecode[1], bytecode[2], bytecode[3], 4]
        elif(format == '22t' or format == '22s' or format == '22c' or format == '22cs'):
            A = bytecode[1] & 0x0f
            B = (bytecode[1] & 0xf0) >> 4
            C = self.intParser(bytecode[2 : 4])
            return [A, B, C, 4]
        elif(format == '30t'):
            if(bytecode[1] != 0x00):
                raise Exception
            return [self.intParser(bytecode[2 : 6]), 6]
        elif(format == '32x'):
            if(bytecode[1] != 0x00):
                raise Exception
            return [self.intParser(bytecode[2 : 4]), self.intParser(bytecode[4 : 6]), 6]
        elif(format == '31i' or format == '31t' or format == '31c'):
            return [bytecode[1], self.intParser(bytecode[2 : 6]), 6]
        elif(format == '35c' or format == '35ms' or format == '35mi'):
            A = (bytecode[1] & 0xf0) >> 4
            B = self.intParser(bytecode[2 : 4])
            C = bytecode[4] & 0x0f
            D = (bytecode[4] & 0xf0) >> 4
            E = bytecode[5] & 0x0f
            F = (bytecode[5] & 0xf0) >> 4
            G = bytecode[1] & 0x0f
            return [A, B, C, D, E, F, G, 6]
        elif(format == '51l'):
            return [bytecode[1], self.intParser(bytecode[2 : 10]), 10]

    def disassemble(self):
        codeString = ''
        tabSpace = 4
        bytecode = self.insns
        i = 0
        while(i < len(bytecode)):
            c = bytecode[i]
            codeString += tabSpace * ' '
            if(c == 0x00):
                codeString += 'nop'
                i += 1
            elif(c == 0x01):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'move ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 2
            elif(c == 0x02):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'move/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 4
            elif(c == 0x03):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = self.intParser(bytecode[i + 2 : i + 4])
                B = self.intParser(bytecode[i + 4 : i + 6])
                codeString += 'move/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 6
            elif(c == 0x04):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'move-wide ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 2
            elif(c == 0x05):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'move-wide/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 4
            elif(c == 0x06):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = self.intParser(bytecode[i + 2 : i + 4])
                B = self.intParser(bytecode[i + 4 : i + 6])
                codeString += 'move-wide/16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 6        
            elif(c == 0x07):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'move-object ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 2
            elif(c == 0x08):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'move-object/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 4
            elif(c == 0x09):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = self.intParser(bytecode[i + 2 : i + 4])
                B = self.intParser(bytecode[i + 4 : i + 6])
                codeString += 'move-object/16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 6
            elif(0x0a <= c and c <= 0x0d):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += ['move-result', 'move-result-wide', 'move-result-object', 'move-exception'][c - 0x0a]
                codeString += ' ' + self.resolveParams(A)
                i += readBytes
            elif(c == 0x0e):
                readBytes += self.__getArguments('10x', bytecode[i:])[0]
                codeString += 'return-void'
                i += readBytes
            elif(0x0f <= c and c <= 0x11):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += ['return', 'return-wide', 'return-object'][c - 0x0f]
                codeString += ' ' + self.resolveParams(A)
                i += readBytes
            elif(c == 0x12):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'const/4 ' + self.resolveParams(A) + ', ' + str(B)
                i += 2
            elif(c == 0x13):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'const/16 ' + self.resolveParams(A) + ', ' + str(B)
                i += 4
            elif(c == 0x14):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 6])
                codeString += 'const ' + self.resolveParams(A) + ', ' + str(B)
                i += 6
            elif(c == 0x15):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4]) << 16
                codeString += 'const/high16 ' + self.resolveParams(A) + ', ' + str(B)
                i += 4
            elif(c == 0x16):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'const-wide/16 ' + self.resolveParams(A) + ', ' + str(B)
                i += 4
            elif(c == 0x1a):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                try:
                    s = self.stringResolver(B).decode(self.encoding)
                    codeString += 'const-string ' + self.resolveParams(A) + ', ' + s
                except(Exception):
                    codeString += 'WARNING: failed to decode string. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'const-string ' + self.resolveParams(A) + ', "' + str(self.stringResolver(B)) + '"'
                i += 4
            elif(c == 0x1b):
                A = bytecode[i + 1]
                Blo = self.intParser(bytecode[i + 2 : i + 4])
                Bhi = self.intParser(bytecode[i + 4 : i + 6]) << 16
                B = Bhi + Blo 
                try:
                    s = self.stringResolver(B).decode(self.encoding)
                    codeString += 'const-string ' + self.resolveParams(A) + ', ' + s
                except(Exception):
                    codeString += 'WARNING: failed to decode string. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'const-string/jumbo ' + self.resolveParams(A) + ', "' + str(self.stringResolver(B)) + '"'
                i += 6
            elif(c == 0x1c):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'const-class ' + self.resolveParams(A) + ', ' + s
                i += 4
            elif(c == 0x1d):
                codeString += 'monitor-enter ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x1e):
                codeString += 'monitor-exit ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x1f):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'check-cast ' + self.resolveParams(A) + ', ' + self.typeResolver(B).decode(self.encoding)
                i += 4  
            elif(c == 0x20):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = self.intParser(bytecode[i + 3 : i + 5])
                codeString += 'instance-of ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', '+ self.typeResolver(C).decode(self.encoding)
                i += 5
            elif(c == 0x21):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                codeString += 'array-length ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
            elif(c == 0x22):
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2: i + 4])
                try:
                    codeString += 'new-instance ' + self.resolveParams(A) + ', ' + self.typeResolver(B).decode(self.encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode type name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'new-instance ' + self.resolveParams(A) + ', ' + str(self.typeResolver(B))
                i += 4
            elif(c == 0x23):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = self.intParser(bytecode[i + 2: i + 4])
                try:
                    codeString += 'new-array ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.typeResolver(C).decode(self.encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode type name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'new-array ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + str(self.typeResolver(C))
                i += 4
            elif(c == 0x27):
                codeString += 'throw ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x28):
                codeString += 'goto ' + str(self.intParser(bytecode[i + 1].to_bytes(1, 'big')))
                i += 2
            elif(c == 0x29):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = self.intParser(bytecode[i + 2 : i + 4])
                codeString += 'goto/16 +' + str(A)
                i += 4
            elif(c == 0x2c):
                #TODO: implement parser for the sparse-switch-payload item, and update codeString accordingly
                A = bytecode[i + 1]
                B = self.intParser(bytecode[i + 2 : i + 6])
                codeString += 'sparse-switch +' + self.resolveParams(A) + ', +' + str(B)
                i += 6
            elif(0x2d <= c and c <= 0x31):
                A, B, C, readBytes = self.__getArguments('23x', bytecode[i:])
                codeString += ['cmpl-float ', 'cmpg-float ', 'cmpl-double ', 'compg-double ', 'cmp-long '][c - 0x2d]
                codeString += ', '.join(self.resolveParams(p) for p in [A, B, C])
                i += readBytes
            elif(0x32 <= c and c <= 0x37):
                A, B, C, readBytes = self.__getArguments('22t', bytecode[i:])
                codeString += ['if-eq ', 'if-ne ', 'if-lt ', 'if-ge ', 'if-gt ', 'if-le '][c - 0x32]
                codeString += ', '.join(self.resolveParams(p) for p in [A, B]) + ' +' + str(C)
                i += readBytes
            elif(0x38 <= c and c <= 0x3d):
                A, B, readBytes = self.__getArguments('21t', bytecode[i:])
                codeString += ['if-eqz ', 'if-nez ', 'if-ltz ', 'if-gez ', 'if-gtz ', 'if-lez '][c - 0x38]
                codeString += self.resolveParams(A) + ', ' + str(B)
                i += readBytes
            elif(0x44 <= c and c <= 0x51):
                A, B, C, readBytes = self.__getArguments('23x', bytecode[i:])
                codeString += ['aget ', 'aget-wide ', 'aget-object ', 'aget-boolean ', 'aget-byte ', 'aget-char ', 'aget-short ', 'aput ', 'aput-wide ', 'aput-object ', 'aput-boolean ', 'aput-byte ', 'aput-char ', 'aput-short '][c - 0x44]
                codeString += ', '.join(self.resolveParams(p) for p in [A, B, C])
                i += readBytes
            elif(0x52 <= c and c <= 0x5f):
                A, B, C, readBytes = self.__getArguments('22c', bytecode[i:])
                codeString += ['iget ', 'iget-wide ', 'iget-object ', 'iget-boolean ', 'iget-byte ', 'iget-char ', 'iget-short ', 'iput ', 'iput-wide ', 'iput-object ', 'iput-boolean ', 'iput-byte ', 'iput-char ', 'iput-short '][c - 0x52]
                codeString += ', '.join(self.resolveParams(p) for p in [A, B])
                codeString += ', ' + self.fieldResolver(C).name.decode(self.encoding)
                i += readBytes
            elif(0x60 <= c and c <= 0x6d):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                codeString += ['sget ', 'sget-wide ', 'sget-object ', 'sget-boolean ', 'sget-byte ', 'sget-char ', 'sget-short ', 'sput ', 'sput-wide ', 'sput-object ', 'sput-boolean ', 'sput-byte ', 'sput-char ', 'sput-short '][c - 0x60]
                try:
                    codeString += self.resolveParams(A) + ', ' + self.fieldResolver(B).name.decode(self.encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode field name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += self.resolveParams(A) + ', ' + str(self.fieldResolver(B).name)
                i += readBytes
            elif(0x6e <= c and c <= 0x72):
                A, B, C, D, E, F, G, readBytes = self.__getArguments('35c', bytecode[i:])
                codeString += ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface'][c - 0x6e]
                codeString += ' {' + ', '.join(self.resolveParams(p) for p in [C, D, E, F, G][:A]) + '}, '
                method = self.methodResolver(B)
                methodClass = method.classId.decode(self.encoding)
                methodParameters = list(map(lambda x: x.decode(self.encoding), method.proto.parameters))
                returnType = method.proto.returnType.decode(self.encoding)
                codeString += methodClass + '->' + method.name.decode(self.encoding) + '(' + ''.join(methodParameters) + ')' + returnType
                i += readBytes
            elif(0xb0 <= c and c <= 0xcf):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += ['add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr', 'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr', 'ushr-int/2addr', 'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr', 'div-long/2addr', 'rem-long/2addr', 'and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr', 'ushr-long/2addr', 'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr', 'div-float/2addr', 'rem-float/2addr', 'add-double/2addr', 'sub-double/2addr', 'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr'][c - 0xb0]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B])
                i += readBytes
            elif(c == 0xfc):
                A, B, C, D, E, F, G, readBytes = self.__getArguments('35c', bytecode[i:])
                codeString += 'invoke-custom'
                codeString += ' {' + ', '.join(self.resolveParams(p) for p in [C, D, E, F, G][:A]) + '}, '
                method = self.methodResolver(B)
                methodClass = method.classId.decode(self.encoding)
                methodParameters = list(map(lambda x: x.decode(self.encoding), method.proto.parameters))
                returnType = method.proto.returnType.decode(self.encoding)
                codeString += methodClass + '->' + method.name.decode(self.encoding) + '(' + ''.join(methodParameters) + ')' + returnType
                i += readBytes
            else:
                codeString += 'Missing implementation for opcode ' + hex(c) + '\n\n'
                break
            codeString += '\n\n'
        return codeString
