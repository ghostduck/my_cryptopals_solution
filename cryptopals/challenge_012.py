import base64
from secrets import token_bytes
from collections import Counter

from tools.crypto_helper import AES
from tools.random_helper import generate_random_bytes

# same 128-bit key to be used many times in this practice -- DON'T DO THIS IN REAL/PRODUCTION
random_AES_key_size = 16
key_bytes = token_bytes(random_AES_key_size)

# target plainbytes encoded in base64 -- DON'T CHECK the content inside
b64_str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
"YnkK"

def get_cipher_info():
    """
        A generic function to find the block size of a block cipher and
        plain bytes (inludes padding), given an oracle that allows bytes injection
    """

    # From Wiki -- https://en.wikipedia.org/wiki/Block_size_(cryptography)
    # Output cannot be shorter than the input because cipher must be reversible
    last_block_size = plain_bytes_size = len(encryption_oracle()) # Maybe padded

    block_size_upper_limit = 100

    # inject repeated bytes and check size
    for i in range(1, block_size_upper_limit + 1):
        injected_bytes = bytearray('q'*i, encoding="utf8")
        cipher_len = len(encryption_oracle(injected_bytes))

        if cipher_len > last_block_size:
            # ciphertext size grows, new block created
            block_size = cipher_len - last_block_size

            # About plainbytes size: If we are using PKCS7 padding, and we make
            # the blackbox to create new block, that new block must be [0x16 * 16].
            #
            # The second last block (original last block) is now filled without padding.
            # We can say our injected bytes pushed the original padded bytes away.

            # original | injected at 6 (i=6)
            # 0 4 8 P  | a e 2 6
            # 1 5 9 P  | b f 3 7
            # 2 6 P P  | c 0 4 8
            # 3 7 P P  | d 1 5 9

            # a-f are the last 6 bytes of last block

            # NOTES about padding and actual plainbyte size:
            # if it is not PKCS7 padding, then this calculation can be wrong
            # if this is PKCS7 padding, then at most it will have 16 bytes padding (full padding block)

            # For example, if plaintext has size of 16, then plain_bytes_size will be 32. Because a whole padded block is added.
            # When i=16, another padded blocked will be created. (1 actual block and 2 full padding blocks)
            # So (plain_bytes_size - i) is the actual plaintext size.

            # Another example, plaintext with size of 10 will have padding of 6, plain_bytes_size is 16.
            # When i=6, padding are filled and new block will be created.
            # This can be generalized for all sizes.

            return (block_size, plain_bytes_size - i)
        elif cipher_len < last_block_size:
            raise ValueError("Ciphertext size decrease when we have more plaintext, no way this is possible")

    # out of loop but still cannot find it
    raise ValueError("Ciphertext size unchanged in loop, need to increase upper limit")

def is_AES_ECB(cipher_bytes):
    # copy from challenege 11
    ctr = Counter()

    for start in range(0, len(cipher_bytes), 16):
        end = start + 16

        output_block_byte = bytes(cipher_bytes[start:end])
        ctr[output_block_byte] += 1

    # check result - most_common() gives an array of tuple with 2 items - (key, count)
    result = ctr.most_common(1)[0]
    return result[1] > 1

def encryption_oracle(injected_bytes=None):
    # This function means: AES-128-ECB(your-string || unknown-string, random-key)

    if injected_bytes is None:
        injected_bytes = bytearray() # default is empty

    bytes_to_encrypt = injected_bytes + base64.standard_b64decode(b64_str)
    cipher_bytes = AES.ECB.encrypt(plain_bytes=bytes_to_encrypt, key_bytes=key_bytes)

    return cipher_bytes

def create_query_dict_from_oracle(previous_n_bytes, block_size):
    limit = block_size - 1

    # assert n == limit, 15 for AES
    if len(previous_n_bytes) != limit:
        raise ValueError("We need the last {} bytes to create attacking dictionary".format(limit))

    atk_dict = dict()

    for i in range(256):
        #  XX  XX  XX  XX
        #  XX  XX  XX  XX
        #  XX  XX  XX  XX
        #  XX  XX  XX '00' <- the byte we want to find, which is the value in atk_dict

        forge_plain_block = bytes(previous_n_bytes + bytes([i]))
        output_block = bytes(encryption_oracle(forge_plain_block)[0:block_size])
        atk_dict[output_block] = i

    return atk_dict

def something():
    # Inject bytes to push:
    # Notation 0A = block 0, at position 10 (0x0A)
    #  Plain block 0  | Plain block 1  |
    #  00  04  08  0C | 10  14  18  1C |
    #  01  05  09  0D | 11  15  19  1D | ...
    #  02  06  0A  0E | 12  16  1A  1E |
    #  03  07  0B  0F | 13  17  1B  1F |

    # Find 1st byte in block 0 by injecting 15 bytes:
    #
    #  XX  XX  XX  XX | 01  05  09  0D |
    #  XX  XX  XX  XX | 02  06  0A  0E | ...
    #  XX  XX  XX  XX | 03  07  0B  0F |
    #  XX  XX  XX '00'| 04  08  0C  10 |

    # Now we can generate all the 256 blocks of 15 XX + 1 extra byte "using the oracle", then find the 1st byte

    # To find the 2nd byte, we inject 14 bytes:
    # Don't forget we already recovered 00
    #
    #  XX  XX  XX  XX | 02  06  0A  0E |
    #  XX  XX  XX  XX | 03  07  0B  0F | ...
    #  XX  XX  XX  00 | 04  08  0C  10 |
    #  XX  XX  XX '01'| 05  09  0D  11 |

    # We can get 16th byte without injection actually, if we found all the previous bytes.
    #
    #  00  04  08  0C | 10  14  18  1C |
    #  01  05  09  0D | 11  15  19  1D | ...
    #  02  06  0A  0E | 12  16  1A  1E |
    #  03  07  0B '0F'| 13  17  1B '1F'|

    # To find the 1st byte in block 1, we inject 15 bytes and use block 0 we just recovered:
    #
    #  XX  XX  XX  XX | 01  05  09  0D |
    #  XX  XX  XX  XX | 02  06  0A  0E | ...
    #  XX  XX  XX  XX | 03  07  0B  0F |
    #  XX  XX  XX  00 | 04  08  0C '10'|

    # In other words, we can decrypt block i if we have the oracle and block i-1.
    # To be concise, we can recover byte i with the 15 bytes before it. (15 = block size - 1)
    # For block 0, we can just forge the arbitrary 15 bytes before it too.

    pass

def byte_at_a_time_ECB_decryption():
    # Aim: Decrypt AES ECB with the oracle/blackbox only!
    # Don't use the key and don't directly read the plain bytes!

    # Step 1: Check block size ... although we already know it is AES
    block_size, plainbyte_size = get_cipher_info() # 138 for plainbyte size, 9 blocks there

    # Step 2: Check if ECB ... although we already know it
    duplicated_injected_bytes = bytearray('9' * 48, encoding="utf-8")
    c_bytes_to_test_ECB = encryption_oracle(duplicated_injected_bytes)

    if is_AES_ECB(c_bytes_to_test_ECB):
        recovered_bytes = bytearray()

        pass


        # Repeat for the remaining bytes
    else:
        raise ValueError("Not ECB -- can't continue")


if __name__ == "__main__":
    byte_at_a_time_ECB_decryption()
    print("End of program")
