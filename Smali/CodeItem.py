class CodeItem:
    def __init__(self, dex, rs, insS, outS, dbg, insns, tries, handlers):
        self.dex = dex
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

    def disassemble(self):
        codeString = ''
        tabSpace = 4
        bytecode = self.insns
        encoding = self.dex.ENCODING
        intParser = self.dex.toUint
        typeResolver = self.dex.getType
        fieldResolver = self.dex.getRawField
        methodResolver = self.dex.getRawMethod
        stringResolver = self.dex.getString 
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
                B = intParser(bytecode[i + 2 : i + 4])
                codeString += 'move/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 4
            elif(c == 0x03):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = intParser(bytecode[i + 2 : i + 4])
                B = intParser(bytecode[i + 4 : i + 6])
                codeString += 'move/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 6
            elif(c == 0x04):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'move-wide ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 2
            elif(c == 0x05):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4])
                codeString += 'move-wide/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 4
            elif(c == 0x06):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = intParser(bytecode[i + 2 : i + 4])
                B = intParser(bytecode[i + 4 : i + 6])
                codeString += 'move-wide/16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 6        
            elif(c == 0x07):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'move-object ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 2
            elif(c == 0x08):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4])
                codeString += 'move-object/from16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 4
            elif(c == 0x09):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = intParser(bytecode[i + 2 : i + 4])
                B = intParser(bytecode[i + 4 : i + 6])
                codeString += 'move-object/16 ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 6
            elif(c == 0x0a):
                codeString += 'move-result ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x0b):
                codeString += 'move-result-wide ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x0c):
                codeString += 'move-result-object ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x0d):
                codeString += 'move-exception ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x0e):
                codeString += 'return-void'
                i += 1
            elif(c == 0x0f):
                codeString += 'return ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x11):
                codeString += 'return-object ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x12):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                codeString += 'const/4 ' + self.resolveParams(A) + ', ' + str(B)
                i += 2
            elif(c == 0x13):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4])
                codeString += 'const/16 ' + self.resolveParams(A) + ', ' + str(B)
                i += 4
            elif(c == 0x14):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 6])
                codeString += 'const ' + self.resolveParams(A) + ', ' + str(B)
                i += 6
            elif(c == 0x15):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4]) << 16
                codeString += 'const/high16 ' + self.resolveParams(A) + ', ' + str(B)
                i += 4
            elif(c == 0x16):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4])
                codeString += 'const-wide/16 ' + self.resolveParams(A) + ', ' + str(B)
                i += 4
#            elif(c == 0x17):
#                A = bytecode[i + 1]
#                B = intParser(bytecode[i + 2 : i + 4])
#                codeString += 'const-wide/32 vAA ' + self.resolveParams(A) + ', ' + str(B)
#                i += 4
            elif(c == 0x1a):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4])
                try:
                    s = stringResolver(B).decode(encoding)
                    codeString += 'const-string ' + self.resolveParams(A) + ', ' + s
                except(Exception):
                    codeString += 'WARNING: failed to decode string. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'const-string ' + self.resolveParams(A) + ', "' + str(stringResolver(B)) + '"'
                i += 4

            elif(c == 0x1b):
                A = bytecode[i + 1]
                Blo = intParser(bytecode[i + 2 : i + 4])
                Bhi = intParser(bytecode[i + 4 : i + 6]) << 16
                B = Bhi + Blo 
                try:
                    s = stringResolver(B).decode(encoding)
                    codeString += 'const-string ' + self.resolveParams(A) + ', ' + s
                except(Exception):
                    codeString += 'WARNING: failed to decode string. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'const-string/jumbo ' + self.resolveParams(A) + ', "' + str(stringResolver(B)) + '"'
                i += 6
            elif(c == 0x1c):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 4])
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
                B = intParser(bytecode[i + 2 : i + 4])
                codeString += 'check-cast ' + self.resolveParams(A) + ', ' + typeResolver(B).decode(encoding)
                i += 4  
            elif(c == 0x20):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = intParser(bytecode[i + 3 : i + 5])
                codeString += 'instance-of ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', '+ typeResolver(C).decode(encoding)
                i += 5
            elif(c == 0x21):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                codeString += 'array-length ' + self.resolveParams(A) + ', ' + self.resolveParams(B)
            elif(c == 0x22):
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2: i + 4])
                try:
                    codeString += 'new-instance ' + self.resolveParams(A) + ', ' + typeResolver(B).decode(encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode type name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'new-instance ' + self.resolveParams(A) + ', ' + str(typeResolver(B))
                i += 4
            elif(c == 0x23):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2: i + 4])
                try:
                    codeString += 'new-array ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + typeResolver(C).decode(encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode type name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += 'new-array ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + str(typeResolver(C))
                i += 4
            elif(c == 0x27):
                codeString += 'throw ' + self.resolveParams(bytecode[i + 1])
                i += 2
            elif(c == 0x28):
                codeString += 'goto ' + str(self.dex.toInt(bytecode[i + 1].to_bytes(1, 'big')))
                i += 2
            elif(c == 0x29):
                zeroByte = bytecode[i + 1]
                if(zeroByte != 0x00):
                    codeString += 'WARNING: non-null byte encountered that should be null.\n' + tabSpace * ' '
                A = intParser(bytecode[i + 2 : i + 4])
                codeString += 'goto/16 +' + str(A)
                i += 4
            elif(c == 0x2c):
                #TODO: implement parser for the sparse-switch-payload item, and update codeString accordingly
                A = bytecode[i + 1]
                B = intParser(bytecode[i + 2 : i + 6])
                codeString += 'sparse-switch +' + self.resolveParams(A) + ', +' + str(B)
                i += 6
            elif(c == 0x2d):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = bytecode[i + 3]
                codeString += 'compl-float ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.resolveParams(C)
                i += 4
            elif(c == 0x2e):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = bytecode[i + 3]
                codeString += 'compg-float ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.resolveParams(C)
                i += 4
            elif(c == 0x2f):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = bytecode[i + 3]
                codeString += 'compl-double ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.resolveParams(C)
                i += 4
            elif(c == 0x30):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = bytecode[i + 3]
                codeString += 'compg-double ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.resolveParams(C)
                i += 4
            elif(c == 0x31):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = bytecode[i + 3]
                codeString += 'comp-long ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.resolveParams(C)
                i += 4
            elif(c == 0x32):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'if-eq ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ' +' + str(C)
                i += 4
            elif(c == 0x33):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'if-ne ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ' +' + str(C)
                i += 4
            elif(c == 0x34):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'if-lt ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ' +' + str(C)
                i += 4
            elif(c == 0x35):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'if-ge ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ' +' + str(C)
                i += 4
            elif(c == 0x36):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'if-gt ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ' +' + str(C)
                i += 4
            elif(c == 0x37):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'if-le ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ' +' + str(C)
                i += 4
            elif(c > 0x37 and c < 0x3e):
                A = bytecode[i + 1]
                B = self.dex.toInt(bytecode[i + 2 : i + 4])
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
                codeString += self.resolveParams(A) + ', ' + str(B)
                i += 4
            elif(c > 0x43 and c < 0x52):
                A = bytecode[i + 1]
                B = bytecode[i + 2]
                C = bytecode[i + 3]
                if(c == 0x44):
                    codeString += 'aget '
                elif(c == 0x45):
                    codeString += 'aget-wide '
                elif(c == 0x46):
                    codeString += 'aget-object '
                elif(c == 0x47):
                    codeString += 'aget-boolean '
                elif(c == 0x48):
                    codeString += 'aget-byte '
                elif(c == 0x49):
                    codeString += 'aget-char '
                elif(c == 0x4a):
                    codeString += 'aget-short '
                elif(c == 0x4b):
                    codeString += 'aput '
                elif(c == 0x4c):
                    codeString += 'aput-wide '
                elif(c == 0x4d):
                    codeString += 'aput-object '
                elif(c == 0x4e):
                    codeString += 'aput-boolean '
                elif(c == 0x4f):
                    codeString += 'aput-byte '
                elif(c == 0x50):
                    codeString += 'aput-char '
                elif(c == 0x51):
                    codeString += 'aput-short '
                codeString += self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + self.resolveParams(C)
                i += 4
            elif(c == 0x52):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x53):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget-object ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x54):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget-object ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x55):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget-boolean '
                codeString += self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x56):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget-byte ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x57):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget-char ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x58):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iget-short ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x59):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x5a):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput-wide ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x5b):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput-object ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x5c):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput-boolean ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x5d):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput-byte ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x5e):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput-char ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
                i += 4
            elif(c == 0x5f):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                C = intParser(bytecode[i + 2 : i + 4])
                codeString += 'iput-short ' + self.resolveParams(A) + ', ' + self.resolveParams(B) + ', ' + fieldResolver(C).name.decode(encoding)
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
                try:
                    codeString += self.resolveParams(A) + ', ' + fieldResolver(B).name.decode(encoding)
                except(Exception):
                    codeString += 'WARNING: failed to decode field name. Leaving it raw.\n'
                    codeString += tabSpace * ' '
                    codeString += self.resolveParams(A) + ', ' + str(fieldResolver(B).name)
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
                    parameters = '{' + self.resolveParams(C) + '}, '
                elif(A == 2):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + '}, '
                elif(A == 3):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + ', ' + self.resolveParams(E) + '}, '
                elif(A == 4):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + ', ' + self.resolveParams(E) + ', ' + self.resolveParams(F) + '}, '
                elif(A == 5):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + ', ' + self.resolveParams(E) + ', ' + self.resolveParams(F) + ', ' + self.resolveParams(G) + '}, '
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
            elif(c > 0xaf and c < 0xd0):
                A = bytecode[i + 1] & 0x0f
                B = (bytecode[i + 1] & 0xf0) >> 4
                if(c == 0xb0):
                    codeString += 'add-int/2addr '
                elif(c == 0xb1):
                    codeString += 'sub-int/2addr '
                elif(c == 0xb2):
                    codeString += 'mul-int/2addr '
                elif(c == 0xb3):
                    codeString += 'div-int/2addr '
                elif(c == 0xb4):
                    codeString += 'rem-int/2addr '
                elif(c == 0xb5):
                    codeString += 'and-int/2addr '
                elif(c == 0xb6):
                    codeString += 'or-int/2addr '
                elif(c == 0xb7):
                    codeString += 'xor-int/2addr '
                elif(c == 0xb8):
                    codeString += 'shl-int/2addr '
                elif(c == 0xb9):
                    codeString += 'shr-int/2addr '
                elif(c == 0xba):
                    codeString += 'ushr-int/2addr '
                elif(c == 0xbb):
                    codeString += 'add-long/2addr '
                elif(c == 0xbc):
                    codeString += 'sub-long/2addr '
                elif(c == 0xbd):
                    codeString += 'mul-long/2addr '
                elif(c == 0xbe):
                    codeString += 'div-long/2addr '
                elif(c == 0xbf):
                    codeString += 'rem-long/2addr '
                elif(c == 0xc0):
                    codeString += 'and-long/2addr '
                elif(c == 0xc1):
                    codeString += 'or-long/2addr '
                elif(c == 0xc2):
                    codeString += 'xor-long/2addr '
                elif(c == 0xc3):
                    codeString += 'shl-long/2addr '
                elif(c == 0xc4):
                    codeString += 'shr-long/2addr '
                elif(c == 0xc5):
                    codeString += 'ushr-long/2addr '
                elif(c == 0xc6):
                    codeString += 'add-float/2addr '
                elif(c == 0xc7):
                    codeString += 'sub-float/2addr '
                elif(c == 0xc8):
                    codeString += 'mul-float/2addr '
                elif(c == 0xc9):
                    codeString += 'div-float/2addr '
                elif(c == 0xca):
                    codeString += 'rem-float/2addr '
                elif(c == 0xcb):
                    codeString += 'add-double/2addr '
                elif(c == 0xcc):
                    codeString += 'sub-double/2addr '
                elif(c == 0xcd):
                    codeString += 'mul-double/2addr '
                elif(c == 0xce):
                    codeString += 'div-double/2addr '
                elif(c == 0xcf):
                    codeString += 'rem-double/2addr '
                codeString += self.resolveParams(A) + ', ' + self.resolveParams(B)
                i += 2
            elif(c == 0xfc):
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
                    parameters = '{' + self.resolveParams(C) + '}, '
                elif(A == 2):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + '}, '
                elif(A == 3):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + ', ' + self.resolveParams(E) + '}, '
                elif(A == 4):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + ', ' + self.resolveParams(E) + ', ' + self.resolveParams(F) + '}, '
                elif(A == 5):
                    parameters = '{' + self.resolveParams(C) + ', ' + self.resolveParams(D) + ', ' + self.resolveParams(E) + ', ' + self.resolveParams(F) + ', ' + self.resolveParams(G) + '}, '
                else:
                    #TODO
                    parameters = '{}'
                codeString += 'invoke-custom ' + parameters + methodResolver(B).name.decode(encoding)
                i += 6
            else:
                codeString += 'Missing implementation for opcode ' + hex(c) + '\n\n'
                break
            codeString += '\n\n'
        return codeString
