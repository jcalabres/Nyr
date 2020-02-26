class Analyzer:
    def overview(dex):
        res = 'Magic: '
        magic = dex.getMagic()
        if(magic[:4] == b'dex\n'):
            res += 'dex\\n\n'
        else:
            res += str(magic[:4]) + '  WARNING: corrupted magic, left raw\n'
        res += 'Version: '
        if(0x2f < magic[4] and magic[4] < 0x40 and 0x2f < magic[5] and magic[5] < 0x40 and 0x2f < magic[6] and magic[6] < 0x40 and magic[7] == 0x00):
            res += magic[4 : 7].decode(dex.ENCODING) + '\n'
        else:
            res += str(magic[4 : 7]) + '  WARNING: corrupted version, left raw\n'
        res += 'Checksum: ' + dex.getChecksum().hex() + '\n'
        res += 'Signature: ' + dex.getSignature().hex() + '\n'
        res += 'File size: '
        realFileSize = dex.getRealSize()
        if(realFileSize == dex.getFileSize()):
            res += str(realFileSize) + '\n'
        else:
            res += str(dex.getFileSize()) + '  WARNING: real file size differs (real size is: ' + str(realFileSize) + ')\n'
        res += 'Header size: '
        if(dex.getHeaderSize() == 0x70):
            res += '0x70\n'
        else:
            res += str(dex.getHeaderSize()) + '  WARNING: header size should be 0x70\n'
        #Endianness cannot be corrupted, as the file would otherwise be unparseable
        res += 'Endianness: '
        if(dex.isBigEndian()):
            res += 'big endian\n'
        else:
            res += 'little endian\n'
        res += 'String count: ' + str(dex.getStringsIdsSize()) + '\n'
        res += 'Type count: ' + str(dex.getTypeIdsSize()) + '\n'
        res += 'Prototype count: ' + str(dex.getProtoIdsSize()) + '\n'
        res += 'Field count: ' + str(dex.getFieldsIdsSize()) + '\n'
        res += 'Method count: ' + str(dex.getMethodIdsSize()) + '\n'
        res += 'Class count: ' + str(dex.getClassDefsSize()) + '\n'
        return res