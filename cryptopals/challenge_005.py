# http://cryptopals.com/sets/1/challenges/5

from itertools import cycle

def encryptXORBytes(plainBytes, keyBytes):
    # keyBytes should be shorter and will keep looping
    # This simple algorithm works even when |keyBytes| <= |plainBytes|
    keyBytesStream = cycle(keyBytes)

    xorBytes = bytearray()
    for b in plainBytes:
        k_b = next(keyBytesStream)
        xorBytes.append(b ^ k_b)
    return xorBytes

def encryptXORwithRepeatedKeys(plaintext, keystr):
    plaintextBytes = bytearray(plaintext, "utf-8")
    keystrBytes = bytearray(keystr, "utf-8")

    xorBytes = encryptXORBytes(plaintextBytes, keystrBytes)
    return xorBytes

def encryptXOR():
    # The website show str1 and str2 as 2 strings, but we just need to str1 + str2 here
    str1 = "Burning 'em, if you ain't quick and nimble\n"
    str2 = "I go crazy when I hear a cymbal"
    keyStr = "ICE"

    output1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
    output2 = "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    output_byte = encryptXORwithRepeatedKeys(str1+str2, keyStr)

    assert(output_byte.hex() == output1 + output2)


if "__main__" == __name__:
    encryptXOR()
    print("End of program")
