# Expect users to import AES, then use AES.ECB.encrypt()/decrypt(), or AES.CBC.encrypt()/decrypt()

from .aes_cipher import AES_encrypt, AES_decrypt
from .padding_helper import PKCS7_add_padding, PKCS7_remove_padding

from abc import ABC, abstractmethod

# helper methods -- seems module functions are good enough
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

class ECB(AES_Base):
    @classmethod
    def encrypt(cls, key_bytes=None, plain_bytes=None):
        return AES_encrypt(key_bytes, plain_bytes)

    @classmethod
    def decrypt(cls, key_bytes=None, cipher_bytes=None):
        return AES_decrypt(key_bytes, cipher_bytes)

class CBC(AES_Base):
    # NOTE: Decorators are not inherited!!
    @classmethod
    def encrypt(cls, key_bytes=None, plain_bytes=None, iv=None):
        iv = bytes(iv)
        check_iv_valid(iv)

        plain_bytes = PKCS7_add_padding(plain_bytes)

        # encrypt starts here
        cipher_bytes = bytearray()

        # Example: size 48 --> 0,1,2
        for i in range(len(plain_bytes) // 16):
            start = i * 16
            end = start + 16

            block_bytes = block_XOR(plain_bytes[start : end], iv)
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

        for i in range(len(cipher_bytes) // 16):
            start = i * 16
            end = start + 16

            block_bytes = cipher_bytes[start : end]

            plain_block_bytes = AES_decrypt(key_bytes, block_bytes)
            plain_bytes.extend(block_XOR(plain_block_bytes, iv))

            iv = block_bytes

        plain_bytes = PKCS7_remove_padding(plain_bytes)
        return plain_bytes
