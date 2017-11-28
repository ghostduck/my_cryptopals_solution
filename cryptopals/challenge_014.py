import base64
from secrets import token_bytes
from collections import Counter

from tools.random_helper import generate_random_bytes
from tools.crypto_helper import AES

# NOTE: Same comments from challenege 12 is removed, since I want to make the comments in this source code related to the random prefix.

random_AES_key_size = 16
key_bytes = token_bytes(random_AES_key_size)

# random but consistent padding prefix of random amount of bytes (1-50 for this time)
# If a random padding is generated everytime the oracle runs, this exercise will be hell difficult
prefix_padding = generate_random_bytes(1, 50)


b64_str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
"YnkK"

def get_cipher_info():
    """
        A generic function to find the block size of a block cipher and
        plain bytes (inludes padding), given an oracle that allows bytes injection
    """

    last_block_size = plain_bytes_size = len(encryption_oracle()) # Maybe padded

    block_size_upper_limit = 100

    # inject repeated bytes and check size
    for i in range(1, block_size_upper_limit + 1):
        injected_bytes = bytearray('q'*i, encoding="utf8")
        cipher_len = len(encryption_oracle(injected_bytes))

        if cipher_len > last_block_size:
            # ciphertext size grows, new block created
            block_size = cipher_len - last_block_size
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
    # Step 1: Check block size ... although we already know it is AES
    block_size, plainbyte_size = get_cipher_info() # 138 for plainbyte size, 9 blocks there

    # Step 2: Check if ECB ... although we already know it
    duplicated_injected_bytes = bytearray('9' * 48, encoding="utf-8")
    dup_bytes_to_test_ECB = encryption_oracle(duplicated_injected_bytes)

    if is_AES_ECB(dup_bytes_to_test_ECB):
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
