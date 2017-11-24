from random import randint, getrandbits
from collections import Counter
from tools.crypto_helper import AES

debug = False

def debug_print(msg):
    if debug:
        print(msg)

def random_byte():
    return randint(0,255)

def gen_random_AES_key():
    return get_random_padding(16,16)

def get_random_padding(low=5, hi=10):
    """Get random amount (from low to hi, including low and hi) of random bytes in a bytearray."""
    pad_len = randint(low, hi)

    pad = bytearray()
    for i in range(pad_len):
        pad.append(random_byte())

    return pad

def encryption_oracle(plain_bytes):
    # another name for this function is random_AES_encrypt() / AES_encryption_blackbox()
    key_bytes = gen_random_AES_key()

    # don't know why -- special requirement: append 5-10 random bytes before and after the plain_bytes
    prepand_pad = get_random_padding()
    append_pad = get_random_padding()

    # Trick: Prepand with slicing
    # plain_bytes[:0] = prepand_pad

    # Or this more simple way
    # plain_bytes = prepand_pad + plain_bytes
    plain_bytes = prepand_pad + plain_bytes + append_pad

    # NOTE: Since 10-20 bytes will be added randomly to the plainbytes, and each block is 16 bytes,
    # if we want to append repeated bytes which will occupy at least 2 blocks ...

    # plain bytes : real plaintext bytes
    # repeated bytes : injected bytes, part of plaintext
    #
    # (5-10) + len(plain bytes) + len(repeated bytes) + (5-10) (+ PKCS7 padding) >= 48 AND len(total) mod 16 == 0
    #

    # Worst case:
    #
    # First padding and plain bytes will consume n blocks + 1 byte, so 15 repeated bytes needs to be consumed
    # - if padding + plain can fill exactly n blocks, then we need 2 blocks of repeating bytes only (32 bytes)
    # - plaintext with length 0 is NOT the worst case: 11 + 16 + 16 = 43 bytes will fail the n blocks + 1 byte case
    #
    # We control the length of repeated bytes, so the end padding doesn't matter
    #
    # As long as repeated bytes have length with at least 47, it is enough to tell it is ECB
    # But we can just use 48 bytes (3 blocks) instead

    # another RNG requirement - 50% to encrypt with CBC, 50% to encrypt with ECB
    use_CBC = getrandbits(1)

    if use_CBC:
        debug_print("Use CBC")
        iv_bytes = get_random_padding(low=16, hi=16)
        cipher_bytes = AES.CBC.encrypt(plain_bytes=plain_bytes, key_bytes=key_bytes, iv=iv_bytes)
    else:
        debug_print("Use ECB")
        cipher_bytes = AES.ECB.encrypt(plain_bytes=plain_bytes, key_bytes=key_bytes)

    return cipher_bytes

def is_AES_ECB(cipher_bytes):
    # The function to detect CBC or ECB in the question ... but I think this function name suits FAR MORE MUCH better

    # It is totally impossible to tell it is ECB or not if we only have many different cipher blocks --
    # could be from CBC, or different plaintext across different blocks (already assuming using same key)

    # Because one tiny bit of change in plaintext/key will change everything in ciphertext (This is also why AES is good)
    # (Change in IV will change the ciphertext of 1st block by 1 bit, but every blocks after will still change a lot)

    # The only thing I can do is the same from previous exercise -- Look for repeated ciphertext across different blocks

    ctr = Counter()

    for start in range(0, len(cipher_bytes), 16):
        end = start + 16

        output_block_byte = bytes(cipher_bytes[start:end])
        ctr[output_block_byte] += 1

    # check result - most_common() gives an array of tuple with 2 items - (key, count)
    result = ctr.most_common(1)[0]
    if result[1] > 1:
        debug_print("Found the repeated bytes -- {} -- occured {} times".format(result[0], result[1]))
        return True
    else:
        return False

def feed_to_orcale(plain_bytes):
    cipher_bytes = encryption_oracle(plain_bytes)

    outcome = is_AES_ECB(cipher_bytes)
    if outcome:
        print("Duplicated blocks found, is ECB")
    else:
        print("Can't find duplicated block, seems CBC?")

    print("")
    return outcome

def test_encryption_oracle():
    exit = False
    input_text = ""

    # just use simple ASCII to simplify the in/out, actually still works for other encoding like UTF-8/16/32
    print("Please input plaintext (simple ASCII) + repeated text (if you want) to feed the orcale")
    while not exit:
        error = False

        in_command = input("Enter _ for same last input, * for the template input(overwrite last input), exit to quit:")
        print("")

        if in_command.lower().strip() in ["exit", "quit"]:
            exit = True
        elif in_command.strip() == "_":
            if not input_text:
                error = True
                print("Come on, there is no previous input, please input something")
        elif in_command.strip() == "*":
            # check comment in encryption_oracle() for the choice of this plain text
            input_text = "1" + "h" * 48
        else:
            input_text = in_command

        if not exit and not error:
            feed_to_orcale(input_text.encode())

if __name__ == "__main__":
    test_encryption_oracle()
    print("End of program")
