from random import randint

# WARNING: THESE BYTES ARE NOT SECURE... should use secrets if you really need a secure one

def random_byte():
    return randint(0,255)

def generate_random_bytes(low, hi):
    """Get random amount (between low and hi, including low and hi) of random bytes in a bytearray."""
    pad_len = randint(low, hi)

    pad = bytearray()
    for i in range(pad_len):
        pad.append(random_byte())

    return pad
