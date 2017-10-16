# http://cryptopals.com/sets/1/challenges/6

from itertools import zip_longest
import base64
import pprint
pp = pprint.PrettyPrinter(indent=4)
from tools.crypto_helper import VigenereBreaker
from tools.crypto_helper import VigenereXORBytes
from itertools import cycle
import string

def HammingDistanceOfBytes(bytes1, bytes2):
    # if length is different, should append the remaining bytes directly, so use zip longest here
    xorBytes = bytearray(b1^b2 for b1, b2 in zip_longest(bytes1, bytes2, fillvalue=0))

    count = 0

    #
    # https://en.wikipedia.org/wiki/Hamming_weight
    #
    # Example:   11010001  Start
    #          & 11010000  <- -1 to extract last bit. The original 1 bit will be 0 after -1. count = 1
    #            --------
    #            110'10000'
    #          & 110'01111' <- -1. Even if original is 0, & makes it back to 0 after -1. The 1s can be ignored actually. count = 2
    #            --------
    #            11000000
    #          & 10111111 <- count = 3
    #            --------
    #            10000000
    #            01111111 <- count = 4
    #            --------
    #            00000000 End
    #

    for b in xorBytes:
        while (b != 0):
            b &= b - 1
            count += 1
    return count

def HammingDistanceOfStrings(str1, str2):
    # Hamming Distance of str1 and str2 is the number of 1 in (str1 XOR str2)
    # Same/similar bytes have lower distance, this is how we look for repetition

    bytes1 = bytearray(str1, "utf-8")
    bytes2 = bytearray(str2, "utf-8")
    return HammingDistanceOfBytes(bytes1,  bytes2)

def testHammingDistance():
    s1 = "this is a test"
    s2 = "wokka wokka!!!"
    assert(HammingDistanceOfStrings(s1, s2) == 37)

def guessKeysize(bytes):
    # store tuples of (size, normalized average distance)
    records = []

    # this limit should be up to len(bytes) / 2 for Vigenere Cipher, but I follow
    # the instruction to try up to 40 this time
    for size in range(2,41):
        total_dist = 0
        pair_count = 0
        start = 0
        end = start + size

        # only do comparison when we can have both b1 and b2
        while end + size < len(bytes):
            # slice index
            # 1 : 0 1, 1 2, 2 3 ...
            # 2 : 0 2, 2 4, 4 6 ...
            # 3 : 0 3, 3 6, 6 9 ...
            b1 = bytes[start:end]
            b2 = bytes[end:end+size]

            total_dist += HammingDistanceOfBytes(b1, b2)
            pair_count += 1

            start += size
            end += size

        # count average
        # (average distance / block size) to normalize result
        t = (size, total_dist/pair_count/size)
        records.append(t)

    # minimum distance at [0]
    records.sort(key=lambda x:x[1])
    pp.pprint(records)
    return records[0][0]

def bruteForceVigenere(encryptedBytes, keysize):
    # create the blocks that we can bruteforce (previous exercise)
    # Step 3
    key = ""
    vb = VigenereBreaker()

    for i in range(keysize):
        # [0::29] -> [1::29] -> ... -> [28::29] will generate all the blocks we want
        block = encryptedBytes[i::keysize]
        k = vb.processEncryptedBytes(block, string.printable)[0]
        key += k

    return key

def decryptVigenere(encryptedBytes, key_str):
    keystrBytes = bytearray(key_str, "utf-8")
    return VigenereXORBytes(encryptedBytes, keystrBytes)

def getFile():
    # get base64 string from file, return as a byte array
    with open("6.txt", "r") as file_source:
        fileStr = file_source.read()
    return base64.standard_b64decode(fileStr)

def decryptXORFile():
    # Hints from the website
    # Step 1: Guess keysize using Hamming Distance
    # Step 2: Base on that keysize, try to get the 1st bytes of each block, which is the same as previous exercise
    # Step 3: Do that for all blocks. Should be able to brute force the answer

    encryptedBytes = getFile()

    # Step 1

    # The trick: cipher bytes1 XOR cipher byte2 = (plaintext bytes1 XOR keybytes) XOR (plaintext bytes2 XOR keybytes)
    # which is plaintext1 XOR plaintext2, if we can guess the key length correctly
    # In other words, wrong key length should give us blocks with higher distance and vice versa

    #keysize = guessKeysize(encryptedBytes)[0]
    # [29, 38, 13, 9, 16] # Best 5 results, 29 (2.75) is much better than others (about 3.15)
    keysize = 29

    # Step 2
    #key_str = bruteForceVigenere(encryptedBytes, keysize)
    key_str = "Terminator X: Bring the noise"

    # Last Step: decrypt it!
    plaintext = decryptVigenere(encryptedBytes, key_str).decode("utf-8")
    print(plaintext)

if "__main__" == __name__:
    decryptXORFile()
    print("End of program")