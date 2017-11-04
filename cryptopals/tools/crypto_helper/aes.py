# Expect users to import AES, then use AES.ECB.encrypt()/decrypt(), or AES.CBC.encrypt()/decrypt()

from .aes_cipher import AES_encrypt, AES_decrypt

class AES_Base(object):
    @classmethod
    def encrypt(key_bytes=None, plain_bytes=None, **kwargs):
        raise NotImplementedError("Don't use base class of AES_Base directly, implement own encrypt() instead")

    @classmethod
    def decrypt(key_bytes=None, cipher_bytes=None, **kwargs):
        raise NotImplementedError("Don't use base class of AES_Base directly, implement own decrypt() instead")

class ECB(AES_Base):
    def encrypt(key_bytes=None, plain_bytes=None):
        return AES_encrypt(key_bytes, plain_bytes)

    def decrypt(key_bytes=None, cipher_bytes=None):
        return AES_decrypt(key_bytes, cipher_bytes)

class CBC(AES_Base):
    def encrypt(key_bytes=None, plain_bytes=None, IV=None):
        pass
        return AES_encrypt(key_bytes, plain_bytes)

    def decrypt(key_bytes=None, cipher_bytes=None):
        pass
        return AES_decrypt(key_bytes, cipher_bytes)
