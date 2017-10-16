import base64

def BytestoBase64(bytes):
    # .decode('utf-8') to remove "b'" at the beginning of string
    return base64.standard_b64encode(bytes).decode('utf-8')

def hexStrtoBytes(hex):
    return bytearray.fromhex(hex)

def testBinHex():
    # Make 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    # to SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected_b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    byte_array = hexStrtoBytes(hex_str)
    print("3rd byte is ", byte_array[2], "0x%x" % byte_array[2])
    out = BytestoBase64(byte_array)
    print(out)
    assert(out == expected_b64)


if "__main__" == __name__:
    testBinHex()
    print("End of program")
