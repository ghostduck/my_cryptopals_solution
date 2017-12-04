# Expect users to import AES, then use AES.ECB.encrypt()/decrypt(), or AES.CBC.encrypt()/decrypt()

from .aes_cipher import AES_encrypt, AES_decrypt
from .padding_helper import PKCS7_add_padding, PKCS7_remove_padding

from abc import ABC, abstractmethod

# helper methods -- seems module functions are good enough
# Altnertaives: Put them inside subclasses, but they would have to call ECB.block_XOR() in ECB.encrypt()/decrypt() ... That feels strange
# Users won't call AES.CBC.block_XOR(), so there are no good reasons to put these helper methods inside class

def check_iv_valid(iv):
    if len(iv) != 16:
        raise ValueError("Block bytes not 128 bits/16 bytes")

def block_XOR(ba1, ba2):
    if len(ba1) != len(ba2):
        raise ValueError("XOR on 2 blocks not having same length")

    return bytearray([(b1^b2) for (b1,b2) in zip(ba1,ba2)])

class AES_Base(ABC):
    @classmethod
    @abstractmethod # This decorator of abstract method should be at the deepest level
    def encrypt(cls, key_bytes=None, plain_bytes=None, **kwargs):
        pass
        #raise NotImplementedError("Don't use base class of AES_Base directly, implement own encrypt() instead")

    @classmethod
    @abstractmethod
    def decrypt(cls, key_bytes=None, cipher_bytes=None, **kwargs):
        pass
        #raise NotImplementedError("Don't use base class of AES_Base directly, implement own decrypt() instead")

class CTR(AES_Base):
    @classmethod
    def encrypt(cls, counter, key_bytes=None, plain_bytes=None):
        """
            AES Counter mode:
            Treat counter as plaintext, encrypt it with key_bytes. Then use the output to XOR part of plain_bytes.
            If there are still plain_bytes left, increment counter then encrypt and XOR again.

            Counter mode can be used as stream cipher.

            counter should be an iteratable.
            next(counter) gives us the 16 bytes, then increment itself.
            Check challenge_018.py for a simple counter, just a function with yield is enough.

            Function returns the whole encrypted bytes of plain_bytes.
        """
        # NOTE1: Not optimized for parallelism ... don't know how to do that actually
        # NOTE2: I can't find any spec/reference about the recommended way for counter (plaintext block for AES) and the way to increment it.
        #        So just use a high-level next() here.
        #        The counter object can be quite complicated -- it can have different format and endian issues.

        output = bytearray()

        for start in range(0, len(plain_bytes), 16):
            end = start + 16

            # Python doesn't raise out of bound errors for this, great
            plain_bytes_as_a_block = plain_bytes[start:end]
            block_bytes = AES_encrypt(key_bytes, next(counter))

            output.extend(cls.block_XOR_for_CTR(block_bytes, plain_bytes_as_a_block))

        return output

    @classmethod
    def decrypt(cls, counter, key_bytes=None, cipher_bytes=None):
        # decryption is same as encryption in Counter Mode
        return cls.encrypt(counter, key_bytes, cipher_bytes)

    @classmethod
    def block_XOR_for_CTR(cls, ba1, ba2):
        # Different from block_XOR(): It doesn't check length.
        # This function just return shorter output if one of the byte array is shorter
        return bytearray([(b1^b2) for (b1,b2) in zip(ba1,ba2)])

class ECB(AES_Base):
    @classmethod
    def encrypt(cls, key_bytes=None, plain_bytes=None):
        # padding first
        plain_bytes = PKCS7_add_padding(plain_bytes, block_size=16)

        if len(plain_bytes) % 16 != 0:
            raise ValueError("Some block does not contain 128 bits/16 bytes")

        cipher_bytes = bytearray()

        for start in range(0, len(plain_bytes), 16):
            end = start + 16

            block_bytes = AES_encrypt(key_bytes, plain_bytes[start:end])
            cipher_bytes.extend(block_bytes)

        return cipher_bytes

    @classmethod
    def decrypt(cls, key_bytes=None, cipher_bytes=None):
        if len(cipher_bytes) % 16 != 0:
            raise ValueError("Some block does not contain 128 bits/16 bytes")

        plain_bytes = bytearray()

        for start in range(0, len(cipher_bytes), 16):
            end = start + 16

            block_bytes = AES_decrypt(key_bytes, cipher_bytes[start : end])
            plain_bytes.extend(block_bytes)

        plain_bytes = PKCS7_remove_padding(plain_bytes)
        return plain_bytes


class CBC(AES_Base):
    # NOTE: Decorators are NOT inherited!!
    @classmethod
    def encrypt(cls, key_bytes=None, plain_bytes=None, iv=None):
        iv = bytes(iv)
        check_iv_valid(iv)

        plain_bytes = PKCS7_add_padding(plain_bytes)

        # encrypt starts here
        cipher_bytes = bytearray()

        for start in range(0, len(plain_bytes), 16):
            end = start + 16

            block_bytes = block_XOR(plain_bytes[start:end], iv)
            # Example: 0:16, 16:32, 32:48 ...

            # the output is also the iv for next block
            iv = AES_encrypt(key_bytes, block_bytes)

            cipher_bytes.extend(iv)

        return cipher_bytes

    @classmethod
    def decrypt(cls, key_bytes=None, cipher_bytes=None, iv=None):
        iv = bytes(iv)
        check_iv_valid(iv)

        # decrypt starts here
        plain_bytes = bytearray()

        for start in range(0, len(cipher_bytes), 16):
            end = start + 16

            block_bytes = cipher_bytes[start : end]

            plain_block_bytes = AES_decrypt(key_bytes, block_bytes)
            plain_bytes.extend(block_XOR(plain_block_bytes, iv))

            iv = block_bytes

        plain_bytes = PKCS7_remove_padding(plain_bytes)
        return plain_bytes

class ECB_single_block(AES_Base):
    # NOTE: No padding for this, since I only expect to encrypt exactly 1 block here

    # If I add padding, then another 16 byte block will also needs to be
    # encrypted as well when plaintext is already 16 bytes

    @classmethod
    def encrypt(cls, key_bytes=None, plain_bytes=None):
        return AES_encrypt(key_bytes, plain_bytes)

    @classmethod
    def decrypt(cls, key_bytes=None, cipher_bytes=None):
        return AES_decrypt(key_bytes, cipher_bytes)
