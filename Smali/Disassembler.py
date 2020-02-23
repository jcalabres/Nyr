class __ParameterResolver:
    def __init__(self, incomingSize, registers):
        self.incomingSize = incomingSize
        self.registers = registers

    def resolve(self, param):
        if(param < self.registers - self.incomingSize):
            return 'v' + str(param)
        else:
            return 'p' + str(param - self.registers + self.incomingSize)

def disassemble(incomingSize, registers, bytecode, encoding, intParser, typeResolver, fieldResolver, methodResolver):
    pResolver = __ParameterResolver(incomingSize, registers).resolve
    codeString = ''
    tabSpace = 4
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
            codeString += 'move ' + pResolver(A) + ', ' + pResolver(B)
            i += 2
        elif(c == 0x02):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            codeString += 'move/from16 ' + pResolver(A) + ', ' + pResolver(B)
            i += 4
        elif(c == 0x07):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            codeString += 'move-object ' + pResolver(A) + ', ' + pResolver(B)
            i += 2
        elif(c == 0x08):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            codeString += 'move-object/from16 ' + pResolver(A) + ', ' + pResolver(B)
            i += 4
        elif(c == 0x0c):
            codeString += 'move-result-object ' + pResolver(bytecode[i + 1])
            i += 2
        elif(c == 0x0e):
            codeString += 'return-void'
            i += 1
        elif(c == 0x0f):
            codeString += 'return ' + pResolver(bytecode[i + 1])
            i += 2
        elif(c == 0x11):
            codeString += 'return-object ' + pResolver(bytecode[i + 1])
            i += 2
        elif(c == 0x12):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            codeString += 'const/4 ' + pResolver(A) + ', ' + str(B)
            i += 2
        elif(c == 0x13):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            codeString += 'const/16 ' + pResolver(A) + ', ' + str(B)
            i += 4
        elif(c == 0x14):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 6])
            codeString += 'const ' + pResolver(A) + ', ' + str(B)
            i += 6
        elif(c == 0x15):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4]) << 16
            codeString += 'const/high16 ' + pResolver(A) + ', ' + str(B)
            i += 4
        elif(c == 0x16):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            codeString += 'const-wide/16 ' + pResolver(A) + ', ' + str(B)
            i += 4
        elif(c == 0x1d):
            codeString += 'monitor-enter ' + pResolver(bytecode[i + 1])
            i += 2
        elif(c == 0x1e):
            codeString += 'monitor-exit ' + pResolver(bytecode[i + 1])
            i += 2
        elif(c == 0x1f):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            codeString += 'check-cast ' + pResolver(A) + ', ' + typeResolver(B).decode(encoding)
            i += 4
        elif(c == 0x22):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2: i + 4])
            codeString += 'new-instance ' + pResolver(A) + ', ' + typeResolver(B).decode(encoding)
            i += 4
        elif(c == 0x28):
            codeString += 'goto +' + pResolver(bytecode[i + 1])
            i += 2
        elif(c == 0x2d):
            A = bytecode[i + 1]
            B = bytecode[i + 2]
            C = bytecode[i + 3]
            codeString += 'compl-float ' + pResolver(A) + ', ' + pResolver(B) + ', ' + pResolver(C)
            i += 4
        elif(c == 0x2e):
            A = bytecode[i + 1]
            B = bytecode[i + 2]
            C = bytecode[i + 3]
            codeString += 'compg-float ' + pResolver(A) + ', ' + pResolver(B) + ', ' + pResolver(C)
            i += 4
        elif(c == 0x2f):
            A = bytecode[i + 1]
            B = bytecode[i + 2]
            C = bytecode[i + 3]
            codeString += 'compl-double ' + pResolver(A) + ', ' + pResolver(B) + ', ' + pResolver(C)
            i += 4
        elif(c == 0x30):
            A = bytecode[i + 1]
            B = bytecode[i + 2]
            C = bytecode[i + 3]
            codeString += 'compg-double ' + pResolver(A) + ', ' + pResolver(B) + ', ' + pResolver(C)
            i += 4
        elif(c == 0x31):
            A = bytecode[i + 1]
            B = bytecode[i + 2]
            C = bytecode[i + 3]
            codeString += 'comp-long ' + pResolver(A) + ', ' + pResolver(B) + ', ' + pResolver(C)
            i += 4
        elif(c == 0x32):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'if-eq ' + pResolver(A) + ', ' + pResolver(B) + ' +' + str(C)
            i += 4
        elif(c == 0x33):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'if-ne ' + pResolver(A) + ', ' + pResolver(B) + ' +' + str(C)
            i += 4
        elif(c == 0x34):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'if-lt ' + pResolver(A) + ', ' + pResolver(B) + ' +' + str(C)
            i += 4
        elif(c == 0x35):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'if-ge ' + pResolver(A) + ', ' + pResolver(B) + ' +' + str(C)
            i += 4
        elif(c == 0x36):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'if-gt ' + pResolver(A) + ', ' + pResolver(B) + ' +' + str(C)
            i += 4
        elif(c == 0x37):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'if-le ' + pResolver(A) + ', ' + pResolver(B) + ' +' + str(C)
            i += 4
        elif(c > 0x37 and c < 0x3e):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            if(c == 0x38):
                codeString += 'if-eqz '
            elif(c == 0x39):
                codeString += 'if-nez '
            elif(c == 0x3a):
                codeString += 'if-ltz '
            elif(c == 0x3b):
                codeString += 'if-gez '
            elif(c == 0x3c):
                codeString += 'if-gtz '
            elif(c == 0x3d):
                codeString += 'if-lez '
            codeString += pResolver(A) + ' +' + str(B)
            i += 4
        elif(c == 0x52):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x53):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget-object ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x54):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget-object ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x55):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget-boolean ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x56):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget-byte ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x57):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget-char ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x58):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iget-short ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x59):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x5a):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput-wide ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x5b):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput-object ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x5c):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput-boolean ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x5d):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput-byte ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x5e):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput-char ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c == 0x5f):
            A = bytecode[i + 1] & 0x0f
            B = (bytecode[i + 1] & 0xf0) >> 4
            C = intParser(bytecode[i + 2 : i + 4])
            codeString += 'iput-short ' + pResolver(A) + ', ' + pResolver(B) + ', ' + typeResolver(C).decode(encoding)
            i += 4
        elif(c > 0x5f and c < 0x6e):
            A = bytecode[i + 1]
            B = intParser(bytecode[i + 2 : i + 4])
            if(c == 0x60):
                codeString += 'sget '
            elif(c == 0x61):
                codeString += 'sget-wide '
            elif(c == 0x62):
                codeString += 'sget-object '
            elif(c == 0x63):
                codeString += 'sget-boolean '
            elif(c == 0x64):
                codeString += 'sget-byte '
            elif(c == 0x65):
                codeString += 'sget-char '
            elif(c == 0x66):
                codeString += 'sget-short '
            elif(c == 0x67):
                codeString += 'sput '
            elif(c == 0x68):
                codeString += 'sput-wide '
            elif(c == 0x69):
                codeString += 'sput-object '
            elif(c == 0x6a):
                codeString += 'sput-boolean '
            elif(c == 0x6b):
                codeString += 'sput-byte '
            elif(c == 0x6c):
                codeString += 'sput-char '
            elif(c == 0x6d):
                codeString += 'sput-short '
            codeString += pResolver(A) + ', ' + fieldResolver(B).name.decode(encoding)
            i += 4
        elif(c > 0x6d and c < 0x73):
            A = (bytecode[i + 1] & 0xf0) >> 4
            G = bytecode[i + 1] & 0x0f
            D = (bytecode[i + 4] & 0xf0) >> 4
            C = bytecode[i + 4] & 0x0f
            F = (bytecode[i + 5] & 0xf0) >> 4
            E = bytecode[i + 5] & 0x0f
            B = intParser(bytecode[i + 2 : i + 4])
            if(A == 0):
                parameters = '{}, '
            elif(A == 1):
                parameters = '{' + pResolver(C) + '}, '
            elif(A == 2):
                parameters = '{' + pResolver(C) + ', ' + pResolver(D) + '}, '
            elif(A == 3):
                parameters = '{' + pResolver(C) + ', ' + pResolver(D) + ', ' + pResolver(E) + '}, '
            elif(A == 4):
                parameters = '{' + pResolver(C) + ', ' + pResolver(D) + ', ' + pResolver(E) + ', ' + pResolver(F) + '}, '
            elif(A == 5):
                parameters = '{' + pResolver(C) + ', ' + pResolver(D) + ', ' + pResolver(E) + ', ' + pResolver(F) + ', ' + pResolver(G) + '}, '
            else:
                #TODO
                parameters = '{}'
            if(c == 0x6e):
                codeString += 'invoke-virtual '
            elif(c == 0x6f):
                codeString += 'invoke-super '
            elif(c == 0x70):
                codeString += 'invoke-direct '
            elif(c == 0x71):
                codeString += 'invoke-static '
            elif(c == 0x72):
                codeString += 'invoke-interface '
            codeString += parameters + methodResolver(B).name.decode(encoding)
            i += 6
        else:
            codeString += 'Missing implementation for opcode ' + hex(c) + '\n\n'
            break
        codeString += '\n\n'
    return codeString
