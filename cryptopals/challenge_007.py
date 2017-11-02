from tools.crypto_helper import AES_decrypt
from itertools import zip_longest
import base64

def grouped(iterable, n):
    "s -> (s0,s1,s2,...sn-1), (sn,sn+1,sn+2,...s2n-1), (s2n,s2n+1,s2n+2,...s3n-1), ..."
    return zip(*[iter(iterable)]*n)

def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def getFile():
    # get base64 string from file, return as a byte array
    with open("7.txt", "r") as file_source:
        fileStr = file_source.read()
    return base64.standard_b64decode(fileStr)

def decryptAESFile():
    encryptedBytes = getFile()
    print("cipher bytes size - ", len(encryptedBytes) )
    keyBytes = bytearray("YELLOW SUBMARINE", "utf-8")

    plainBytes = bytearray()

    for i in grouped(encryptedBytes, 16):
        c_p = bytearray(i)
        plainBytes.extend(AES_decrypt(keyBytes, c_p))

    plaintext = plainBytes.decode("utf-8")
    print(plaintext)

if "__main__" == __name__:
    decryptAESFile()
    print("End of program")