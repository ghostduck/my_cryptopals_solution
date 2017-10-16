from itertools import cycle

def VigenereXORBytes(plainBytes, keyBytes):
    # keyBytes should be shorter and will keep looping
    # This simple algorithm works even when |keyBytes| <= |plainBytes|
    keyBytesStream = cycle(keyBytes)

    xorBytes = bytearray()
    for b in plainBytes:
        k_b = next(keyBytesStream)
        xorBytes.append(b ^ k_b)
    return xorBytes

def VigenereXORwithRepeatedKeys(plaintext, keystr):
    plaintextBytes = bytearray(plaintext, "utf-8")
    keystrBytes = bytearray(keystr, "utf-8")
    
    xorBytes = VigenereXORBytes(plaintextBytes, keystrBytes)
    return xorBytes