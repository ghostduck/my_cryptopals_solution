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
print("prefix len: {}".format(len(prefix_padding)))


b64_str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
"YnkK"

def check_valid_offset_bytes(first_injected_byte_block_index, total_inject_size, block_size):
    # Start filling in repeating bytes (32-47), aim to find padding offset (0-15) by
    # creating 2 identical output block AND make sure NO injected bytes added to plain bytes

    # For example, padding size is 3 + n*16, offset is 13
    # R A A A |          |          | P
    # R A A A | (all As) | (all As) | P
    # R A A A |          |          | P
    # A A A A |          |          | ...
    #

    # Worst case:
    # B1      | B2      | B3      |
    # ---------------------------------
    # R A A A | A A A A | A A A A | P
    # A A A A | A A A A | A A A A | P
    # A A A A | A A A A | A A A A | ....
    # A A A A | A A A A | A A A P |
    # ---------------------------------
    # ^ index points to R

    # 1. If R == A (in 1/256, not a low chance !!), we will see B1 == B2 when we inject 32 bytes of A.
    # We think the offset is 0 but this is WRONG because 1 byte of A goes to the plain bytes block (B3).
    # Even though we can still recover the bytes, this is quite dumb to "recover" an extra byte due to our programming error.

    # 2. If that P in B3 == A, assume R =/= A. Then B2 == B3, when we inject 46 bytes and the offset is 14.
    # This is wrong since offset should be 15. 1 plainbyte will be lost on further recovery.
    # However, we actually knows P. Also, A is not chosen by random at runtime, so this is not that big problem.

    # Conclusion: Have to try 3 different bytes for the same length for an 100% correct offset.

    for i in range(3):
        injected_bytes_pattern = bytearray([i] * total_inject_size)
        output = encryption_oracle(injected_bytes_pattern)

        k = first_injected_byte_block_index
        b1 = output[k:k+block_size]

        k += block_size
        b2 = output[k:k+block_size]

        k += block_size
        b3 = output[k:k+block_size]

        if (b1 != b2) and (b2 != b3):
            return False

    return True

def find_padding_offset_from_orcale(block_size, first_injected_byte_block_index):
    for offset in range(0, block_size):
        total_inject_size = 2 * block_size + offset # 32 - 47

        if check_valid_offset_bytes(first_injected_byte_block_index, total_inject_size, block_size):
            return offset

    raise ValueError("Can't create/find 2 same output block after injecting {} bytes!!! Please debug".format(3 * block_size))


def find_first_different_block(cipher_bytes1, cipher_bytes2, block_size):
    """
        If there are differences in cipher_bytes (in a block), return index of 1st byte in that block.
        If they are the same, return -1.
        If they have different length, and everything is the same (except those longer blocks), return index
        of 1st byte in longer block, which is len(shorter_byte) + 1
    """

    # make sure byte2 is the shorter block
    if len(cipher_bytes2) > len(cipher_bytes1):
        cipher_bytes1, cipher_bytes2 = cipher_bytes2, cipher_bytes1

    # compare
    for start in range(0, len(cipher_bytes2), block_size):
        end = start + block_size
        if cipher_bytes1[start:end] != cipher_bytes2[start:end]:
            return start

    # everything is equal, check their length
    if len(cipher_bytes2) == len(cipher_bytes1):
        return -1
    else:
        return len(cipher_bytes2) + 1

def create_block_counter(cipher_bytes, block_size):
    # copy from challenege 11
    ctr = Counter()

    for start in range(0, len(cipher_bytes), block_size):
        end = start + block_size

        output_block_byte = bytes(cipher_bytes[start:end])
        ctr[output_block_byte] += 1

    return ctr

def get_pad_size(block_size):

    # Legend(R: random padding, P: plaintext, A: injected attacking byte)

    # Worst case consideration:
    #  R  R  R  R | P
    #  R  R  R  R | P
    #  R  R  R  R | ...
    #  R  R  R 'P'|
    #
    # If you inject A, but it is the same as 1st byte of P. Then the output is the same, and we will check the wrong block ...
    #  R  R  R  R | 'P'
    #  R  R  R  R |  P
    #  R  R  R  R |  P ...
    #  R  R  R 'A'|
    # -------------------
    # same output | next block "may" change, so we may point to this block
    #
    # So we have to try 2 differnt byte to pad and use the best result

    output_without_injection = encryption_oracle()

    one_byte_injection_a = encryption_oracle(bytearray([0]))
    one_byte_injection_b = encryption_oracle(bytearray([1]))

    first_injected_byte_block_index = min(find_first_different_block(output_without_injection, one_byte_injection_a, block_size),
                                          find_first_different_block(output_without_injection, one_byte_injection_b, block_size))

    if first_injected_byte_block_index == -1:
        raise ValueError("We have same output block after changing 1 byte in input")

    # About the index and padding

    # "Normal" cases: padding also included in same block
    # [R] R  R  P |  P
    #  R  R  R  P |  P
    #  R  R 'A' P |  P ...
    #  R  R  P  P |  P
    # ------------------
    #  ^ index points to []

    # Edge case: point to a block without padding, if padding prefix alone can fill a block.
    #  R  R  R  R |['A']
    #  R  R  R  R |  P
    #  R  R  R  R |  P ...
    #  R  R  R  R |  P
    #--------------------
    #                ^ index points to []

    offset = find_padding_offset_from_orcale(block_size, first_injected_byte_block_index)

    # The Maths -- Just check this table:
    # i = first injected byte block index, o = offset, s = pad size
    # i  | o  | s
    # --------------
    # 16 |  0 | 16
    # 16 |  1 | 31
    # 16 |  2 | 30
    # ...
    # 16 | 15 | 17

    return first_injected_byte_block_index + block_size - offset

def get_cipher_info():
    """
        A generic function to find the block size of a block cipher,
        given an oracle that allows bytes injection.

        Difference from Q12: We can't get plaintext size since it is mixed with random padding.
    """

    output_without_injection = encryption_oracle() # includes random prefix and PKCS7 padding

    last_total_block_size = len(output_without_injection)
    block_size_upper_limit = 100

    # inject repeated bytes and check size
    for i in range(1, block_size_upper_limit + 1):
        injected_bytes = bytearray('q'*i, encoding="utf8")
        cipher_len = len(encryption_oracle(injected_bytes))

        if cipher_len > last_total_block_size:
            # ciphertext size grows, new block created
            block_size = cipher_len - last_total_block_size
            return block_size
        elif cipher_len < last_total_block_size:
            raise ValueError("Ciphertext size decrease when we have more plaintext, no way this is possible")

    # out of loop but still cannot find it
    raise ValueError("Ciphertext size unchanged in loop, need to increase upper limit")

def find_plainbytes_size(prefix_pad_offset, prefix_pad_size, block_size):
    # almost the same logic as get_cipher_info()

    offset_bytes = bytearray([5]* prefix_pad_offset)
    total_cipher_size = len(encryption_oracle(offset_bytes))

    # keep injecting bytes until a 16*16 PKCS7 block is created
    for i in range(1, block_size + 1):
        injected_bytes = offset_bytes + bytearray([9] * i)
        new_cipher_size = len(encryption_oracle(injected_bytes))

        if new_cipher_size > total_cipher_size:
            return total_cipher_size - prefix_pad_size - i - prefix_pad_offset
        elif new_cipher_size < total_cipher_size:
            raise ValueError("Ciphertext size decrease when we have more plaintext, no way this is possible")

    raise ValueError("Ciphertext size unchanged after injecting {} bytes, please debug".format(block_size))

def is_AES_ECB(cipher_bytes, block_size):
    ctr = create_block_counter(cipher_bytes, block_size)

    # check result - most_common() gives an array of tuple with 2 items - (key, count)
    result = ctr.most_common(1)[0]
    return result[1] > 1

def encryption_oracle(injected_bytes=None):
    # This function means: AES-128-ECB(padding || your-string || unknown-string, random-key)

    if injected_bytes is None:
        injected_bytes = bytearray() # default is empty

    # NEW! We have a random prefix here!
    bytes_to_encrypt = prefix_padding + injected_bytes + base64.standard_b64decode(b64_str)
    cipher_bytes = AES.ECB.encrypt(plain_bytes=bytes_to_encrypt, key_bytes=key_bytes)

    return cipher_bytes

def create_query_dict_from_oracle(previous_n_bytes, block_size, injected_bytes_start_index, prefix_pad_offset_bytes):
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
        bytes_to_inject = prefix_pad_offset_bytes + forge_plain_block

        start = injected_bytes_start_index
        end = start + block_size

        # need to shift our index due to the random prefix
        output_block = bytes(encryption_oracle(bytes_to_inject)[start:end])
        atk_dict[output_block] = i

    return atk_dict

def recover_bytes_from_orcale(block_size, prefix_pad_size):
    # initialize vars
    plain_bytes = bytearray()
    pad_size = block_size - 1

    prefix_pad_offset = block_size - (prefix_pad_size % block_size)
    prefix_pad_offset_bytes = bytearray([6] * prefix_pad_offset)
    plainbyte_size = find_plainbytes_size(prefix_pad_offset, prefix_pad_size, block_size)

    print("length of plain bytes from what I write = {}".format(plainbyte_size))

    plain_bytes_start_index = prefix_pad_size + prefix_pad_offset # the block right after padding + padding_offset

    # recovering bytes
    for i in range(plainbyte_size):
        # setup
        inject_size = pad_size - (i % block_size) # 0-15
        bytes_to_fill_in = bytearray('9' * inject_size, encoding="utf-8") # not including the offset padding
        bytes_to_inject = prefix_pad_offset_bytes + bytes_to_fill_in

        if i < pad_size:
            # arbitrary 15 bytes, needs to contain known bytes if any
            previous_bytes = bytes_to_fill_in + plain_bytes
        else:
            previous_bytes = plain_bytes[-pad_size:]

        atk_dict = create_query_dict_from_oracle(previous_bytes, block_size, plain_bytes_start_index, prefix_pad_offset_bytes)

        # Start the attack from here
        # Feed padding bytes into the blackbox
        output = encryption_oracle(bytes_to_inject)

        # Check result against dict to find the byte
        # [start:end] refers to the whole block
        block_shift = i // block_size
        start = plain_bytes_start_index + block_shift * block_size
        end = start + block_size

        bytes_to_check = bytes(output[start:end])
        plain_byte = atk_dict[bytes_to_check]

        plain_bytes.append(plain_byte)

        # print("Recovered byte {} : {}".format(i, plain_bytes.decode("utf-8")))

    return plain_bytes

def byte_at_a_time_ECB_decryption():
    # Step 1: Check block size ... although we already know it is AES
    # NOTE: We don't know plain byte size currently. We will only know only if we can
    # inject 2 blocks of same bytes (in get_pad_size())
    block_size = get_cipher_info()

    # Step 2: Check if ECB ... although we already know it
    duplicated_injected_bytes = bytearray('9' * 48, encoding="utf-8")
    dup_bytes_to_test_ECB = encryption_oracle(duplicated_injected_bytes)

    if is_AES_ECB(dup_bytes_to_test_ECB, block_size):
        print("Starting to recover bytes ... this takes quite long")

        plain_bytes = bytes(base64.standard_b64decode(b64_str))
        # print("length of plain bytes = {}".format(len(plain_bytes)))

        prefix_pad_size = get_pad_size(block_size)
        assert prefix_pad_size == len(prefix_padding)

        recovered_bytes = recover_bytes_from_orcale(block_size, prefix_pad_size)
        recovered_string = str(recovered_bytes.decode('utf-8'))

        print("See if the recovered byte the same as plain byte")
        plain_bytes = bytes(base64.standard_b64decode(b64_str))

        assert plain_bytes == bytes(recovered_bytes)
        print("I get them correctly, even with a random but fixed prefix PogChamp. Check the result")
        print(recovered_string)

    else:
        raise ValueError("Not ECB -- can't continue")


if __name__ == "__main__":
    byte_at_a_time_ECB_decryption()
    print("End of program")
