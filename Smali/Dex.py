import Smali.Disassembler as Disassembler
import Smali.Encoders as Encoder

class Dex:
    NO_INDEX = 0xffffffff
    ENCODING = 'UTF-8'

    def __init__(self, filePath):
        f = open(filePath, 'rb')
        self.dex = f.read()
        f.close()

        self.MAGIC = self.dex[:8]
        self.CHECKSUM = self.dex[8:12]
        self.SIGNATURE = self.dex[12:32]
        self.FILE_SIZE = self.dex[32:36]
        self.HEADER_SIZE = self.dex[36:40]
        self.ENDIAN_TAG = self.dex[40:44]
        self.LINK_SIZE = self.dex[44:48]
        self.LINK_OFF = self.dex[48:52]
        self.MAP_OFF = self.dex[52:56]
        self.STRINGS_IDS_SIZE = self.dex[56:60]
        self.STRINGS_IDS_OFF = self.dex[60:64]
        self.TYPE_IDS_SIZE = self.dex[64:68]
        self.TYPE_IDS_OFF = self.dex[68:72]
        self.PROTO_IDS_SIZE = self.dex[72:76]
        self.PROTO_IDS_OFF = self.dex[76:80]
        self.FIELDS_IDS_SIZE = self.dex[80:84]
        self.FIELDS_IDS_OFF = self.dex[84:88]
        self.METHOD_IDS_SIZE = self.dex[88:92]
        self.METHOD_IDS_OFF = self.dex[92:96]
        self.CLASS_DEFS_SIZE = self.dex[96:100]
        self.CLASS_DEFS_OFF = self.dex[100:104]
        self.DATA_SIZE = self.dex[104:108]
        self.DATA_OFF = self.dex[108:112]

        if(self.ENDIAN_TAG == b'\x12\x34\x56\x78'):
            self.mBigEndian = True
        elif(self.ENDIAN_TAG == b'\x78\x56\x34\x12'):
            self.mBigEndian = False
        else:
            raise Exception #TODO: proper exception
        
        return

    def toInt(self, n):
        if(self.mBigEndian):
            return int.from_bytes(n, 'big')
        return int.from_bytes(n, 'little')

    def getMagic(self):
        return self.MAGIC

    def getChecksum(self):
        return self.CHECKSUM

    def getSignature(self):
        return self.SIGNATURE

    def getFileSize(self):
        return self.toInt(self.FILE_SIZE)

    def getHeaderSize(self):
        return self.toInt(self.HEADER_SIZE)

    def getEndianTag(self):
        return self.ENDIAN_TAG
    
    def getLinkSize(self):
        return self.toInt(self.LINK_SIZE)

    def getLinkOff(self):
        return self.toInt(self.LINK_OFF)

    def getMapOff(self):
        return self.toInt(self.MAP_OFF)

    def getStringsIdsSize(self):
        return self.toInt(self.STRINGS_IDS_SIZE)

    def getStringsIdsOff(self):
        return self.toInt(self.STRINGS_IDS_OFF)

    def getTypeIdsSize(self):
        return self.toInt(self.TYPE_IDS_SIZE)

    def getTypeIdsOff(self):
        return self.toInt(self.TYPE_IDS_OFF)

    def getProtoIdsSize(self): #Thanks Proto!
        return self.toInt(self.PROTO_IDS_SIZE)

    def getProtoIdsOff(self):
        return self.toInt(self.PROTO_IDS_OFF)

    def getFieldsIdsSize(self):
        return self.toInt(self.FIELDS_IDS_SIZE)

    def getFieldsIdsOff(self):
        return self.toInt(self.FIELDS_IDS_OFF)

    def getMethodIdsSize(self):
        return self.toInt(self.METHOD_IDS_SIZE)

    def getMethodIdsOff(self):
        return self.toInt(self.METHOD_IDS_OFF)

    def getClassDefsSize(self):
        return self.toInt(self.CLASS_DEFS_SIZE)

    def getClassDefsOff(self):
        return self.toInt(self.CLASS_DEFS_OFF)

    def getDataSize(self):
        return self.toInt(self.DATA_SIZE)

    def getDataOff(self):
        return self.toInt(self.DATA_OFF)

    def isBigEndian(self):
        return self.mBigEndian

    def getString(self, n):
        stringOff = self.toInt(self.dex[self.getStringsIdsOff() + 4 * n : self.getStringsIdsOff() + 4 * (n + 1)])
        stringSize, internalOff = Encoder.uleb128Decode(self.dex[stringOff :])
        return self.dex[stringOff + internalOff : stringOff + internalOff + stringSize]

    def getType(self, n):
        typeIdsStart = self.getTypeIdsOff()
        return self.getString(self.toInt(self.dex[typeIdsStart + 4 * n : typeIdsStart + 4 * (n + 1)]))

    def __parseTypeList(self, offset):
        typeList = []
        listSize = self.toInt(self.dex[offset:offset + 4])
        for i in range(0, 2 * listSize, 2):
            typeList.append(self.getType(self.toInt(self.dex[offset + i + 4: offset + i + 6])))
        return typeList

    def getPrototype(self, n):
        protoStart = self.getProtoIdsOff() + 12 * n
        shorty = self.getString(self.toInt(self.dex[protoStart : protoStart + 4]))
        ret = self.getType(self.toInt(self.dex[protoStart + 4:protoStart + 8]))
        parametersOff = self.toInt(self.dex[protoStart + 8:protoStart + 12])
        if(parametersOff == 0):
            parameters = []
        else:
            parameters = self.__parseTypeList(parametersOff)
        return Prototype(shorty, ret, parameters)

    def getRawField(self, n):
        fieldStart = self.getFieldsIdsOff() + 8 * n
        classId = self.getType(self.toInt(self.dex[fieldStart : fieldStart + 2]))
        typeId = self.getType(self.toInt(self.dex[fieldStart + 2 : fieldStart + 4]))
        name = self.getString(self.toInt(self.dex[fieldStart + 4 : fieldStart + 8]))
        return RawField(classId, typeId, name)

    def getRawMethod(self, n):
        methodStart = self.getMethodIdsOff() + 8 * n
        classId = self.getType(self.toInt(self.dex[methodStart : methodStart + 2]))
        proto = self.getPrototype(self.toInt(self.dex[methodStart + 2 : methodStart + 4]))
        name = self.getString(self.toInt(self.dex[methodStart + 4 : methodStart + 8]))
        return RawMethod(classId, proto, name)
    
    def getClass(self, n):
        classStart = self.getClassDefsOff() + 32 * n
        classId = self.getType(self.toInt(self.dex[classStart : classStart + 4]))
        accessFlags = self.toInt(self.dex[classStart + 4 : classStart + 8])
        superclassIdx = self.toInt(self.dex[classStart + 8 : classStart + 12])
        if(superclassIdx == self.NO_INDEX):
            superclass = ''
        else:
            superclass = self.getType(superclassIdx)
        interfacesOff = self.toInt(self.dex[classStart + 12 : classStart + 16])
        if(interfacesOff == 0):
            interfaces = []
        else:
            interfaces = self.__parseTypeList(interfacesOff)
        sourceFileIdx = self.toInt(self.dex[classStart + 16 : classStart + 20])
        if(sourceFileIdx == self.NO_INDEX):
            sourceFile = ''
        else:
            sourceFile = self.getString(sourceFileIdx)
        annotationsOff = self.toInt(self.dex[classStart + 20 : classStart + 24])
        if(annotationsOff == 0):
            annotations = None
        else:
            #TODO
            annotations = None
        classDataOff = self.toInt(self.dex[classStart + 24 : classStart + 28])
        if(classDataOff == 0):
            classData = [[], [], [], []]
        else:
            classData = self.__parseClassData(classDataOff)
        staticValuesOff = self.toInt(self.dex[classStart + 28 : classStart + 32])
        if(staticValuesOff == 0):
            staticValues = []
        else:
            #TODO
            staticValues = []
        return Class(self, classId, accessFlags, superclass, interfaces, sourceFile, annotations, classData, staticValues)

    def getClassByName(self, name):
        for i in range(self.toInt(self.CLASS_DEFS_SIZE)):
            c = self.getClass(i)
            if(c.classId.decode(self.ENCODING) == name):
                return c
        return None

    def __parseClassData(self, offset):
        internalOff = 0
        staticFieldsSize, readBytes = Encoder.uleb128Decode(self.dex[offset:])
        internalOff = internalOff + readBytes
        instanceFieldsSize, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
        internalOff = internalOff + readBytes
        directMethodsSize, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
        internalOff = internalOff + readBytes
        virtualMethodsSize, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
        internalOff = internalOff + readBytes
        staticFields, readBytes = self.__parseEncodedFields(offset + internalOff, staticFieldsSize)
        internalOff = internalOff + readBytes
        instanceFields, readBytes = self.__parseEncodedFields(offset + internalOff, instanceFieldsSize)
        internalOff = internalOff + readBytes
        directMethods, readBytes = self.__parseEncodedMethods(offset + internalOff, directMethodsSize)
        internalOff = internalOff + readBytes
        virtualMethods, readBytes = self.__parseEncodedMethods(offset + internalOff, virtualMethodsSize)
        return [staticFields, instanceFields, directMethods, virtualMethods]

    def __parseEncodedFields(self, offset, size):
        fields = []
        internalOff = 0
        fieldIdx = 0
        for i in range(size):
            fieldIdxDiff, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
            fieldIdx = fieldIdx + fieldIdxDiff
            internalOff = internalOff + readBytes
            accessFlags, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
            internalOff = internalOff + readBytes
            rawField = self.getRawField(fieldIdx)
            field = Field.fromRawField(rawField, accessFlags)
            fields.append(field)
        return [fields, internalOff]

    def __parseEncodedMethods(self, offset, size):
        methods = []
        internalOff = 0
        methodIdx = 0
        for i in range(size):
            methodIdxDiff, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
            methodIdx += methodIdxDiff
            rawMethod = self.getRawMethod(methodIdx)
            internalOff += readBytes
            accessFlags, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
            internalOff += readBytes
            codeOff, readBytes = Encoder.uleb128Decode(self.dex[offset + internalOff:])
            internalOff += readBytes
            if(codeOff != 0):
                codeItem = self.__parseCodeItem(codeOff)
            else:
                codeItem = None
            methods.append(Method.fromRawMethod(rawMethod, accessFlags, codeItem))
        return [methods, internalOff]


    def __parseCodeItem(self, offset):
        registersSize = self.toInt(self.dex[offset : offset + 2])
        insSize = self.toInt(self.dex[offset + 2 : offset  + 4])
        outsSize = self.toInt(self.dex[offset + 4 : offset + 6])
        triesSize  = self.toInt(self.dex[offset + 6 : offset + 8])
        debugInfoOff = self.toInt(self.dex[offset + 8 : offset + 12])
        insnsSize = self.toInt(self.dex[offset + 12 : offset + 16])
        insns = self.dex[offset + 16 : offset + 16 + 2 * insnsSize]
        #TODO
        dbg = None
        tries = None
        handlers = None
        return CodeItem(registersSize, insSize, outsSize, dbg, insns, tries, handlers)
    
class Prototype:
    def __init__(self, s, r, p):
        self.shortyDescriptor = s
        self.returnType = r
        self.parameters = p
        return

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

    def __str__(self):
        res = ''
        #TODO: classId
        res += self.name.decode(Dex.ENCODING) + '('
        for parameter in self.proto.parameters:
            res += parameter.decode(Dex.ENCODING) + ' '
        if(len(self.proto.parameters) > 0):
            res = res[:-1]
        res += ') returns ' + self.proto.returnType.decode(Dex.ENCODING)
        return res

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

    def __str__(self):
        res = self.classId.decode(Dex.ENCODING) + '\n'
        for method in (self.directMethods + self.virtualMethods):
            res += method.__str__() + '\n'
            res += Disassembler.disassemble(method.code.incomingSize, method.code.registers, method.code.insns, Dex.ENCODING, self.dex.toInt, self.dex.getType, self.dex.getRawField, self.dex.getRawMethod)
        return res

class ClassDataItem:
    def __init__(self, sf, insf, dm, vm):
        self.staticFields = sf
        self.instanceFields = insf
        self.directMethods = dm
        self.virtualMethods = vm
        return

class CodeItem:
    def __init__(self, rs, insS, outS, dbg, insns, tries, handlers):
        self.registers = rs
        self.incomingSize = insS
        self.outgoingSize = outS
        self.debugInfo = dbg
        self.insns = insns
        self.tries = tries
        self.handlers = handlers
        return
