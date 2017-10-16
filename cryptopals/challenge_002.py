def XORbyteStr(s1,s2):
    ba1 = bytearray.fromhex(s1)
    ba2 = bytearray.fromhex(s2)
    ba_xor = bytearray()

    for b1,b2 in zip(ba1,ba2):
        ba_xor.append(b1 ^ b2)

    return ba_xor

def byteXOR():

    byte1  = "1c0111001f010100061a024b53535009181c"
    byte2  = "686974207468652062756c6c277320657965"
    output = "746865206b696420646f6e277420706c6179"

    out = XORbyteStr(byte1, byte2)
    out_str = out.hex()
    print(out_str)
    assert(out_str == output)


if "__main__" == __name__:
    byteXOR()
    print("End of program")
