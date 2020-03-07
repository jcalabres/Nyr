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
        elif(format == '3rc' or format == '3rms' or format == "3rmi"):
            arguments = []
            A = self.intParser(bytecode[1])
            B = self.intParser(bytecode[2 : 4])
            C = bytecode[4 : 6]
            N = C + A - 1
            arguments.append(C)
            paramIndex = 6
            for i in range(1,N):
                arguments.append(bytecode[paramIndex : paramIndex + 2])
                paramIndex+=2
            arguments.append(6+paramIndex)
            return arguments
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
                readBytes = self.__getArguments('10x', bytecode[i:])
                codeString += 'nop'
            elif(c == 0x01):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += 'move ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x02):
                A, B, readBytes = self.__getArguments('22x', bytecode[i:])
                codeString += 'move/from16 ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x03):
                A, B, readBytes = self.__getArguments('32x', bytecode[i:])
                codeString += 'move/16 ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x04):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += 'move-wide ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x05):
                A, B, readBytes = self.__getArguments('22x', bytecode[i:])
                codeString += 'move-wide/from16 ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x06):
                A, B, readBytes = self.__getArguments('32x', bytecode[i:])
                codeString += 'move-wide/from16 ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x07):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += 'move-object ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x08):
                A, B, readBytes = self.__getArguments('22x', bytecode[i:])
                codeString += 'move-object/from16 ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x09):
                A, B, readBytes = self.__getArguments('32x', bytecode[i:])
                codeString += 'move-object/from16 ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(0x0a <= c and c <= 0x0d):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += ['move-result', 'move-result-wide', 'move-result-object', 'move-exception'][c - 0x0a]
                codeString += ' ' + self.resolveParams(A)         
            elif(c == 0x0e):
                readBytes += self.__getArguments('10x', bytecode[i:])[0]
                codeString += 'return-void'
            elif(0x0f <= c and c <= 0x11):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += ['return', 'return-wide', 'return-object'][c - 0x0f]
                codeString += ' ' + self.resolveParams(A)
            elif(c == 0x12):
                A, B, readBytes = self.__getArguments('11n', bytecode[i:])
                codeString += 'const/4 ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x13):
                A, B, readBytes = self.__getArguments('21s', bytecode[i:])
                codeString += 'const/16 ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x14):
                A, B, readBytes = self.__getArguments('31i', bytecode[i:])
                codeString += 'const ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x15):
                A, B, readBytes = self.__getArguments('21h', bytecode[i:])
                codeString += 'const/high16 ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x16):
                A, B, readBytes = self.__getArguments('21s', bytecode[i:])
                codeString += 'const-wide/16 ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x17):
                A, B, readBytes = self.__getArguments('31i', bytecode[i:])
                codeString += 'const-wide/32 ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x18):
                A, B, readBytes = self.__getArguments('51l', bytecode[i:])
                codeString += 'const-wide ' + self.resolveParams(A) + ', ' + str(B)
            elif(c == 0x19):
                A, B, readBytes = self.__getArguments('21h', bytecode[i:])
                codeString += 'const-wide/high16 ' + self.resolveParams(A) + ', ' + str(B)  
            elif(c == 0x1a):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                try:
                    s = self.stringResolver(B).decode(self.encoding)
                    codeString += 'const-string ' + self.resolveParams(A) + ', ' + s
                except(Exception):
                    codeString += 'WARNING: failed to decode string. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'const-string ' + self.resolveParams(A) + ', "' + str(self.stringResolver(B)) + '"'
            elif(c == 0x1b):
                A, B, readBytes = self.__getArguments('31c', bytecode[i:])
                try:
                    s = self.stringResolver(B).decode(self.encoding)
                    codeString += 'const-string ' + self.resolveParams(A) + ', ' + s
                except(Exception):
                    codeString += 'WARNING: failed to decode string. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'const-string/jumbo ' + self.resolveParams(A) + ', "' + str(self.stringResolver(B)) + '"'
            elif(c == 0x1c):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                codeString += 'const-class ' + self.resolveParams(A) + ', ' + self.typeResolver(B).decode(self.encoding)
            elif(c == 0x1d):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += 'monitor-enter ' + self.resolveParams(A)
            elif(c == 0x1e):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += 'monitor-exit ' + self.resolveParams(A)
            elif(c == 0x1f):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                codeString += 'check-cast ' + self.resolveParams(A) + ', ' + self.typeResolver(B).decode(self.encoding)  
            elif(c == 0x20):
                A, B, C, readBytes = self.__getArguments('22c', bytecode[i:])
                codeString += 'instance-of ' + ', '.join(self.resolveParams(p) for p in [A, B]) + ', '+ self.typeResolver(C).decode(self.encoding)
            elif(c == 0x21):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += 'array-length ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(c == 0x22):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                try:
                    codeString += 'new-instance ' + self.resolveParams(A) + ', ' + self.typeResolver(B).decode(self.encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode type name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'new-instance ' + self.resolveParams(A) + ', ' + str(self.typeResolver(B))
            elif(c == 0x23):
                A, B, C, readBytes = self.__getArguments('22c', bytecode[i:])
                try:
                    codeString += 'new-array ' + ', '.join(self.resolveParams(p) for p in [A, B]) + ', ' + self.typeResolver(C).decode(self.encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode type name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'new-array ' + ', '.join(self.resolveParams(p) for p in [A, B]) + ', ' + str(self.typeResolver(C))
            elif(c == 0x24):
                A, B, C, D, E, F, G, readBytes = self.__getArguments('35c', bytecode[i:])
                codeString += 'filled-new-array'
                codeString += ' {' + ', '.join(self.resolveParams(p) for p in [C, D, E, F, G][:A]) + '}, '
                codeString += self.typeResolver(B)
            elif(c == 0x25):
                arguments = self.__getArguments('3rc', bytecode[i:])
                A, B, C = arguments[0:3]
                nargs = arguments[3:-1]
                readBytes = arguments[-1]
                codeString += 'filled-new-array/range '
                codeString += ' {' + self.resolveParams(C) + ', '.join(self.resolveParams(p) for p in nargs) + '}, '
                codeString += self.typeResolver(B)
            elif(c == 0x26):
                #TODO: implement parser for the sparse-switch-payload item, and update codeString accordingly
                A, B, readBytes = self.__getArguments('31t', bytecode[i:])
                codeString += 'fill-array-data +' + self.resolveParams(A) + ', +' + str(B)
            elif(c == 0x27):
                A, readBytes = self.__getArguments('11x', bytecode[i:])
                codeString += 'throw ' + self.resolveParams(A)
            elif(c == 0x28):
                A, readBytes = self.__getArguments('10t', bytecode[i:])
                codeString += 'goto ' + str(self.intParser(A.to_bytes(1, 'big')))
            elif(c == 0x29):
                A, readBytes = self.__getArguments('20t', bytecode[i:])
                codeString += 'goto/16 +' + str(A)
            elif(c == 0x2a):
                A, readBytes = self.__getArguments('30t', bytecode[i:])
                codeString += 'goto/32 +' + str(A)
             elif(c == 0x2b):
                #TODO: implement parser for the sparse-switch-payload item, and update codeString accordingly
                A, B, readBytes = self.__getArguments('31t', bytecode[i:])
                codeString += 'packed-switch +' + self.resolveParams(A) + ', +' + str(B)
            elif(c == 0x2c):
                #TODO: implement parser for the sparse-switch-payload item, and update codeString accordingly
                A, B, readBytes = self.__getArguments('31t', bytecode[i:])
                codeString += 'sparse-switch +' + self.resolveParams(A) + ', +' + str(B)
            elif(0x2d <= c and c <= 0x31):
                A, B, C, readBytes = self.__getArguments('23x', bytecode[i:])
                codeString += ['cmpl-float', 'cmpg-float', 'cmpl-double', 'compg-double', 'cmp-long'][c - 0x2d]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B, C])
            elif(0x32 <= c and c <= 0x37):
                A, B, C, readBytes = self.__getArguments('22t', bytecode[i:])
                codeString += ['if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le'][c - 0x32]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B]) + ' +' + str(C)
            elif(0x38 <= c and c <= 0x3d):
                A, B, readBytes = self.__getArguments('21t', bytecode[i:])
                codeString += ['if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez'][c - 0x38]
                codeString += ' ' + self.resolveParams(A) + ', ' + str(B)
            elif(0x44 <= c and c <= 0x51):
                A, B, C, readBytes = self.__getArguments('23x', bytecode[i:])
                codeString += ['aget ', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short', 'aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short'][c - 0x44]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B, C])
            elif(0x52 <= c and c <= 0x5f):
                A, B, C, readBytes = self.__getArguments('22c', bytecode[i:])
                codeString += ['iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short', 'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short'][c - 0x52]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B])
                codeString += ', ' + self.fieldResolver(C).name.decode(self.encoding)
            elif(0x60 <= c and c <= 0x6d):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                codeString += ['sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short', 'sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short'][c - 0x60]
                try:
                    codeString += ' ' + self.resolveParams(A) + ', ' + self.fieldResolver(B).name.decode(self.encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode field name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += ' ' + self.resolveParams(A) + ', ' + str(self.fieldResolver(B).name)
            elif(0x6e <= c and c <= 0x72):
                A, B, C, D, E, F, G, readBytes = self.__getArguments('35c', bytecode[i:])
                codeString += ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface'][c - 0x6e]
                codeString += ' {' + ', '.join(self.resolveParams(p) for p in [C, D, E, F, G][:A]) + '}, '
                method = self.methodResolver(B)
                methodClass = method.classId.decode(self.encoding)
                methodParameters = list(map(lambda x: x.decode(self.encoding), method.proto.parameters))
                returnType = method.proto.returnType.decode(self.encoding)
                codeString += methodClass + '->' + method.name.decode(self.encoding) + '(' + ''.join(methodParameters) + ')' + returnType
            elif(0x74 <= c and c <= 0x78):
                arguments = self.__getArguments('3rc', bytecode[i:])
                A, B, C = arguments[0:3]
                nargs = arguments[3:-1]
                readBytes = arguments[-1]
                codeString += ['invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range', 'invoke-static/range', 'invoke-interface/range'][c - 0x74]
                codeString += ' {' + self.resolveParams(C) + ', '.join(self.resolveParams(p) for p in nargs) + '}, '
                method = self.methodResolver(B)
                codeString += method.name.decode(self.encoding)
            elif(0x7b <= c and c <= 0x8f):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += ['neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double', 'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float', 'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double', 'double-to-int', 'double-to-long', 'double-to-float', 'int-to-byte', 'int-to-char', 'int-to-short'][c - 0x7b]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B])
            elif(0x90 <= c and c <= 0xaf):
                A, B, C, readBytes = self.__getArguments('23x', bytecode[i:])
                codeString += ['add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int', 'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long', 'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float', 'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double'][c - 0x90]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B, C])
            elif(0xb0 <= c and c <= 0xcf):
                A, B, readBytes = self.__getArguments('12x', bytecode[i:])
                codeString += ['add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr', 'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr', 'ushr-int/2addr', 'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr', 'div-long/2addr', 'rem-long/2addr', 'and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr', 'ushr-long/2addr', 'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr', 'div-float/2addr', 'rem-float/2addr', 'add-double/2addr', 'sub-double/2addr', 'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr'][c - 0xb0]
                codeString += ' ' + ', '.join(self.resolveParams(p) for p in [A, B])
            #TODO d0..d7, d8..e2, e3..f9, fa, fb
            elif(c == 0xfc):
                A, B, C, D, E, F, G, readBytes = self.__getArguments('35c', bytecode[i:])
                codeString += 'invoke-custom'
                codeString += ' {' + ', '.join(self.resolveParams(p) for p in [C, D, E, F, G][:A]) + '}, '
                method = self.methodResolver(B)
                methodClass = method.classId.decode(self.encoding)
                methodParameters = list(map(lambda x: x.decode(self.encoding), method.proto.parameters))
                returnType = method.proto.returnType.decode(self.encoding)
                codeString += methodClass + '->' + method.name.decode(self.encoding) + '(' + ''.join(methodParameters) + ')' + returnType
            elif(c == 0xfd):
                arguments = self.__getArguments('3rc', bytecode[i:])
                A, B, C = arguments[0:3]
                nargs = arguments[3:-1]
                readBytes = arguments[-1]
                codeString += 'invoke-custom/range'
                codeString += ' {' + self.resolveParams(C) + ', '.join(self.resolveParams(p) for p in nargs) + '}, '
                method = self.methodResolver(B)
                methodClass = method.classId.decode(self.encoding)
                methodParameters = list(map(lambda x: x.decode(self.encoding), method.proto.parameters))
                returnType = method.proto.returnType.decode(self.encoding)
                codeString += methodClass + '->' + method.name.decode(self.encoding) + '(' + ''.join(methodParameters) + ')' + returnType
            elif(c == 0xfe):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                codeString += 'const-method-handle ' + self.resolveParams(A) + ', ' + str(B)         
            elif(c == 0xff):
                A, B, readBytes = self.__getArguments('21c', bytecode[i:])
                codeString += 'const-method-type ' + self.resolveParams(A) + ', ' + str(B)
            else:
                codeString += 'Missing implementation for opcode ' + hex(c) + '\n\n'
                break
            codeString += '\n\n'
            i += readBytes
        return codeString
