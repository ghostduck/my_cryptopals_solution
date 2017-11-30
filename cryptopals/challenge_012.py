import base64
from secrets import token_bytes
from collections import Counter

from tools.crypto_helper import AES

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

def is_AES_ECB(cipher_bytes, block_size):
    # copy from challenege 11
    ctr = Counter()

    for start in range(0, len(cipher_bytes), block_size):
        end = start + block_size

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
    """
        Use previous_n_bytes + 1 byte to feed a block to oracle, then return a
        dictionary of output block to value of last plain bytes.
    """
    limit = block_size - 1

    # assert n == limit, 15 for AES
    if len(previous_n_bytes) != limit:
        raise ValueError("We need exactly last {} bytes to create attacking dictionary".format(limit))

    atk_dict = dict()

    for i in range(256):
        #  XX  XX  XX  XX
        #  XX  XX  XX  XX
        #  XX  XX  XX  XX
        #  XX  XX  XX '??' <- ?? is the byte we want to find, which is the value in atk_dict. XX are from previous_n_bytes

        forge_plain_block = previous_n_bytes + bytes([i])

        # we want the first block only, then store result to dict
        output_block = bytes(encryption_oracle(forge_plain_block)[0:block_size])
        atk_dict[output_block] = i

    return atk_dict

def recover_bytes_from_orcale(block_size, plainbyte_size):
    # Inject bytes to push:
    # Notation 0A = block 0, at position 10 (0x0A)
    #  Plain block 0  | Plain block 1  |
    #  00  04  08  0C | 10  14  18  1C |
    #  01  05  09  0D | 11  15  19  1D | ...
    #  02  06  0A  0E | 12  16  1A  1E |
    #  03  07  0B  0F | 13  17  1B  1F |

    # The spirit of the attck: Push the byte we want to recover to the end of block,
    # then we pad and use the orcale to find the value (1 out of 256 bytes).

    # Find 1st byte in block 0 by injecting 15 bytes: (15 bytes for all 1st byte in all blocks)
    #
    #  XX  XX  XX  XX | 01  05  09  0D |
    #  XX  XX  XX  XX | 02  06  0A  0E | ...
    #  XX  XX  XX  XX | 03  07  0B  0F |
    #  XX  XX  XX '00'| 04  08  0C  10 |

    # Now we can generate all the 256 blocks of 15 XX + 1 extra byte "using the oracle". (create_query_dict_from_oracle())
    # Then we check the output of the block against our dictionary (which is also created by the oracle) to get the plain byte.

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

    # In this case, those XX can be 01,02,... anything. We don't really care about their value. We only want something to be padded.
    # In other words, the padding block and attack dictionary are the same for block 0. For block 1 and so on, they are different.
    # For the injected bytes, they can be of any value as long as the length is correct.

    # For 2nd byte in block 2:
    #  XX  XX  XX  XX | 02  06  0A  0E |
    #  XX  XX  XX  XX | 03  07  0B  0F | ...
    #  XX  XX  XX  00 | 04  08  0C  10 |
    #  XX  XX  XX  01 | 05  09  0D '11'|

    # To sum up, we can decrypt block i if we have the oracle and block i-1.
    # To be concise, we can recover byte i with the 15 bytes before it. (15 = block size - 1)
    # For block 0, we can just craft an arbitrary 15 bytes before it.

    plain_bytes = bytearray()
    pad_size = block_size - 1

    for i in range(plainbyte_size):
        # setup
        inject_size = pad_size - (i % block_size) # 0-15
        bytes_to_inject = bytearray('9' * inject_size, encoding="utf-8")

        if i < pad_size:
            # arbitrary 15 bytes, needs to contain known bytes if any
            previous_bytes = bytes_to_inject + plain_bytes
        else:
            previous_bytes = plain_bytes[-pad_size:]

        atk_dict = create_query_dict_from_oracle(previous_bytes, block_size)

        # Start the attack from here
        # Feed padding bytes into the blackbox
        output = encryption_oracle(bytes_to_inject)

        # Check result against dict to find the byte
        # [start:end] refers to the whole block
        start = (i // block_size) * block_size # 0,16,32 ...
        end = start + block_size

        bytes_to_check = bytes(output[start:end])
        plain_byte = atk_dict[bytes_to_check]

        plain_bytes.append(plain_byte)

    return plain_bytes

def byte_at_a_time_ECB_decryption():
    # Aim: Decrypt AES ECB with the oracle/blackbox only!
    # Don't use the key and don't directly read the plain bytes!

    # Step 1: Check block size ... although we already know it is AES
    block_size, plainbyte_size = get_cipher_info() # 138 for plainbyte size, 9 blocks there

    # Step 2: Check if ECB ... although we already know it
    duplicated_injected_bytes = bytearray('9' * 48, encoding="utf-8")
    dup_bytes_to_test_ECB = encryption_oracle(duplicated_injected_bytes)

    if is_AES_ECB(dup_bytes_to_test_ECB, block_size):
        print("Starting to recover bytes ... this takes quite long")
        # About complexity: To recover 1 byte, we need to call the orcale 256 times to create a dictionary.
        # Then we feed in a block to it, finally we check against the dictionary and get the value.
        #
        # Each time we call the oracle, it will encrypt everything ... which is quite slow,
        # even though we only want first block for the dictionary.
        recovered_bytes = recover_bytes_from_orcale(block_size, plainbyte_size)

        # Byte to string
        recovered_string = str(recovered_bytes.decode('utf-8'))

        print("See if the recovered byte the same as plain byte")
        plain_bytes = bytes(base64.standard_b64decode(b64_str))

        assert plain_bytes == bytes(recovered_bytes)
        print("I get them correctly PogChamp. Check the result")
        print(recovered_string)

    else:
        raise ValueError("Not ECB -- can't continue")


if __name__ == "__main__":
    byte_at_a_time_ECB_decryption()
    print("End of program")
