# block_size is in terms of byte
def PKCS7_add_padding(b, block_size=16):
    if block_size >= 256:
        raise ValueError("Block size too large to pad, needs to be within 255")

    # block size of 1 seems similar to null in null-terminated string, with value of 1 at the end while allowing 1s in between...
    # strange, but still valid actually
    if block_size <= 0:
        raise ValueError("Block size too small to pad, needs to be at least 1")

    # b is byte to pad

    padding_byte_size = block_size if len(b) % block_size == 0 else block_size - (len(b) % block_size)
    padding_bytes = bytearray([padding_byte_size]) * padding_byte_size

    # return new bytearray
    k = bytearray(b)
    k.extend(padding_bytes)

    return k

def PKCS7_remove_padding(b, strict_checking=True):
    # read value of last byte (say k), then skip the last k bytes in b

    # Python slicing syntax is so great
    last_byte = b[-1]

    # Not sure about this ... just return b, only raise if strict_checking == True, or forbids last_byte to be 0
    if last_byte < 1:
        raise ValueError("Last byte needs to be at least 1 for PKCS7 padding")

    if strict_checking:
        # check all those bytes are padding bytes or not
        padding_bytes = b[-last_byte : ]
        #expected_padding_bytes = bytes([last_byte]) * last_byte

        # Why not using all()? Because I don't want to return earlier ...
        # But I think it doesn't matter since it is only used for removing plaintext padding
        #if not all(v == last_byte for v in padding_bytes):
        if padding_bytes != bytes([last_byte]) * last_byte :
            raise ValueError("Invalid padding for PKCS7")

    return  b[0: -last_byte]