def uleb128Decode(enc):
    value = 0
    iteration = 0
    isLastByte = False
    for c in enc:
        if(isLastByte):
            break
        if(c & 0x80 == 0x00):
            isLastByte = True
        currentValue = 0x7f & c
        value = value + (currentValue << (7 * iteration))
        iteration = iteration + 1
    if(not isLastByte):
        raise Exception #TODO: not finished parsing
    return [value, iteration]

