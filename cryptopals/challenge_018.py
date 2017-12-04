import base64
from struct import pack

from tools.crypto_helper import AES

secret_str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
key_str = "YELLOW SUBMARINE"

def counter(nonce, start_value):
    # back to basic -- endian: https://betterexplained.com/articles/understanding-big-and-little-endian-byte-order/
    # Given a 32-bit address layout like this, they all store a byte
    #
    # Address    | Byte
    # 0x56789000 | 0x12
    # 0x56789001 | 0x56
    # 0x56789002 | 0x78
    # 0x56789003 | 0x9A
    #
    # Horizontal view:
    # |0x12|0x56|0x78|0x9A|
    # | 00 | 01 | 02 | 03 |

    # Assume there is a byte pointer pointing to 0x56789000, if you increment it, it points to 0x56789001 no matter it is big or little endian.
    # Big-Endian and Little-Endian matters when data are spread across different bytes.

    # If they are treated as 2 16-bit integers ...
    # Big-Endian will treat them as 0x1256 and 0x789A -- "the first byte (lowest address) is the biggest (MSB)"
    # Little-Endian will treat them as 0x5612 and 0x9A78 -- "the first byte is smallest"

    # If they are a 32-bit integer ...
    # Big-Endian: 0x1256789A
    # Little-Endian: 0x9A785612

    # If we declear an 32-bit integer with 0x1256789A in Little-Endian machine, it will be stored this way
    # |0x9A|0x78|0x56|0x12|
    # | 00 | 01 | 02 | 03 |

    i = start_value
    while True:
        # From question:
        #  format=64 bit unsigned little endian nonce,
        #         64 bit little endian block count (byte count / 16)

        # '<' means Little-Endian, Q is unsigned long long (64 bit integer), we have 2 of them
        yield pack("<QQ", nonce, i)

        i += 1
        i %= 2**64 # Make sure it is within range of 64-bit integers

        if i == 0:
            raise ValueError("WARNING: counter overflowed -- same stream byte will be reused if you continue")

def test_CTR():
    c = counter(0,0) # check the function for counter specification

    cipher_bytes = base64.standard_b64decode(secret_str)
    key_bytes = bytes(key_str, encoding="utf-8")

    # The most important line here
    plain_bytes = AES.CTR.decrypt(c, key_bytes, cipher_bytes)

    output = plain_bytes.decode(encoding="utf-8")

    # It ends with an extra space
    assert output.strip() == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby"
    print("AES Counter mode works!!")

if "__main__" == __name__:
    test_CTR()
    print("End of program")
