from secrets import token_bytes
import urllib.parse

from tools.crypto_helper import AES


AES_block_size = 16
key_bytes = token_bytes(AES_block_size) # random 128-bit key
iv_bytes = token_bytes(AES_block_size)

# basic functions
def input_comment(user_input):
    # the black box function
    user_input = sanitize_data(user_input)

    prefix = "comment1=cooking%20MCs;userdata=" # length: 32, excatly fits 2 blocks!
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon" # length: 42
    return encrypt_comment(prefix + user_input + suffix)

def encrypt_comment(comment_str):
    plain_bytes = comment_str.encode(encoding="utf-8")
    return AES.CBC.encrypt(plain_bytes=plain_bytes, key_bytes=key_bytes, iv=iv_bytes)

def decrypt_and_check_admin(cipher_bytes):
    # Our aim is to trick this function to return True by breaking crypto
    is_admin_str = ";admin=true;" # length: 12
    plain_bytes = AES.CBC.decrypt(cipher_bytes=cipher_bytes, key_bytes=key_bytes, iv=iv_bytes)

    return is_admin_str.encode(encoding="utf-8") in plain_bytes

def sanitize_data(data):
    # don't allow ';' and '=' -- make sure to attack this with crypto but not inputing "data;admin=true"
    return urllib.parse.quote(data)

# functions for attacking

def CBC_bitflipping():
    normal_input = "duck_admin_true_" # len: 16, the content in 3rd block

if "__main__" == __name__:
    CBC_bitflipping()
    print("End of program")