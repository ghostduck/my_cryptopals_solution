from secrets import token_bytes
import urllib.parse

from tools.crypto_helper import AES


AES_block_size = 16
key_bytes = token_bytes(AES_block_size) # random 128-bit key
iv_bytes = token_bytes(AES_block_size)

# basic functions
def input_then_encrypt_comment(user_input):
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

    # uncomment to check the content
    # print("decrypt result: ", plain_bytes.decode(encoding="utf-8", errors="replace"))
    # print("decrypt result: ", plain_bytes)
    return is_admin_str.encode(encoding="utf-8") in plain_bytes

def sanitize_data(data):
    # don't allow ';' and '=' -- make sure to attack this with crypto but not inputing "data;admin=true"
    return urllib.parse.quote(data)

# functions for attacking
def forge_cipher_blocks(cipher_bytes, expected_rigged_change, block_index_to_change):
    if block_index_to_change < 1:
        raise ValueError("Can't tamper block 0 or negative blocks -- we have no access to IV, or wrong index")

    block_size = 16

    start_index_of_block_before = block_size * (block_index_to_change - 1)
    start, end = start_index_of_block_before, start_index_of_block_before + block_size

    block_to_change = cipher_bytes[start:end]

    # start the work here
    for t in expected_rigged_change:
        i, original_char, change_to_char = t

        # Check the ASCII graph comment in tamper_encrypted_bytes() for details, in ...(1)
        block_to_change[i] ^= ord(original_char) ^ ord(change_to_char)

    cipher_bytes[start:end] = block_to_change
    return cipher_bytes


def tamper_encrypted_bytes(cipher_bytes):
    # for "duck_admin_true_", we want to change to ...
    # pos 4 (0 based index) from '_' to ';', 10 from '_' to '=', 15 from '_' to ';'
    expected_rigged_change = [(4,'_',';'), (10, '_' ,'='), (15, '_', ';')]

    # Explanation:
    # To decrypt block 2 (0 based index), the code is (ECB decrypt(block 2, key) XOR block 1)
    # We don't have key here. So we have to tamper block 1 (and it will be undecryptable, but we don't care) to make the result we want.
    block_index_to_change = 2

    # As long as we know some info about the format of plaintext, we can tamper it bit-by-bit to change the output.
    # In this challenege, we already know the plaintext. This further reduce the difficulty.

    #
    #          block 3
    #             |
    #             V
    #     AES ECB decrypt(key)
    #             |
    #             V
    # block 2 -> XOR
    #             |
    #             V
    #         plaintext 3
    #

    # block 2 and block 3 is available to us.
    # We can't change block 3.

    # Shown in formula:
    # Plaintext = last block XOR decrypted bytes (block 3 after AES), which is the same as
    # decrypted bytes = last block XOR Plaintext
    #
    # We can't change decrypted bytes, so we have to change last block or plaintext
    # If we knows plaintext, we can cancel them out and forge a outcome.
    #
    # (1)
    # plaintext XOR (plaintext XOR forged result) = decrypted bytes XOR last block XOR (plaintext XOR forged result)
    # forged result = decrypted bytes XOR last block XOR (plaintext XOR forged result)
    #
    # If we don't know the plaintext, we can just try to change something ...
    # plaintext (XOR some changes) = decrypted bytes XOR last block (XOR some changes)
    #
    # So knowing anything about plaintext, or see the plaintext itself can help a lot on forging the result.
    #
    # If we have the decryption blackbox (key included but we don't know the value and IV), we can get the plaintext, so
    # we can actually forge the result we want too.

    # NOTE: pass a copy of cipher_bytes, since we don't want to change the original content
    forged_blocks = forge_cipher_blocks(cipher_bytes[:], expected_rigged_change, block_index_to_change)
    return forged_blocks

def CBC_bitflipping():
    # test can't directly inject ";admin=true;" first
    should_fail_input = ";admin=true;"
    should_fail_cipher_bytes = input_then_encrypt_comment(should_fail_input)
    assert False == decrypt_and_check_admin(should_fail_cipher_bytes)
    print("OK, we can't directly inject admin=true")

    # Our attempt to break the crypto
    normal_input = "duck_admin_true_" # len: 16, the content in 3rd block
    cipher_bytes = input_then_encrypt_comment(normal_input)

    rigged_cipher_bytes = tamper_encrypted_bytes(cipher_bytes)
    assert True == decrypt_and_check_admin(rigged_cipher_bytes)
    print("We did it! Bitflipping CBC to manipulate output without keys!")

    # About the question: "Before you implement this attack, answer this question: why does CBC mode have this property?"
    # I try to answer it here, but no one will tell me if this is correct or not...
    #
    # CBC design wants to "chain" all the blocks. block 2 relies on block 1, and block 1 relies on block 0 (which is known as IV).
    # CBC encryption of block i: ECB Encrypt(plain block i XOR cipher output block i-1), for the first block use IV as the previous block
    # So change 1 bit of plaintext or IV will change all the following output on encryption. -- This is for the encryption stage.

    # So given we have all the ciphertexts, IV and key...
    # CBC decryption of block i: ECB Decrypt(Cipher block i) XOR cipher block i-1, IV is the previous block for 1st block

    # Under this design, decryption of a block needs previous cipher block, all other blocks do not matter.
    # One benefit is that for any transmission error in any bit in 1 block, it only corrupts itself and next block.
    # This attack abuse this benefit.

if "__main__" == __name__:
    CBC_bitflipping()
    print("End of program")