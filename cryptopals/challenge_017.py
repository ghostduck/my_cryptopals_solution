import base64
import random
from secrets import token_bytes

from tools.crypto_helper import AES, PKCS7PaddingError, PKCS7_remove_padding
from tools.misc_helper import print_bytes_with_description


debug = False
AES_block_size = 16
key_bytes = token_bytes(AES_block_size) # random 128-bit key
iv_bytes = token_bytes(AES_block_size)

random_secret_strs = [
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

# I don't really know why they want to encrypt these base64 strings, but not the byte contents inside them ...
secret_str = random.choice(random_secret_strs) #　the object to encrypt

def debug_print(s):
    if (debug):
        print(s)

# basic functions
def has_valid_padding(cipher_bytes):
    """
        Decrypt cipher_bytes using AES CBC mode, then ...
        - return True if it has valid padding (PKCS7)
        - otherwise (catch an Exception for padding) return False
    """

    # NOTE: This function is the padding oracle. It only return True or False on padding result.
    # BUT THIS IS ENOUGH for us to recover ALL the intermediate object!!!
    # About the name of "padding oracle": This oracle (blackbox) only tells you if it has a valid padding or not.
    try:
        # Actually IV doesn't matter in this attack
        plain_bytes = AES.CBC.decrypt(cipher_bytes=cipher_bytes, key_bytes=key_bytes, iv=iv_bytes)
    except PKCS7PaddingError as e:
        # debug_print(e)
        return False

    # NOTE: plain_bytes are without paddings now
    # print_bytes_with_description(plain_bytes, "Find a valid padding block! This is the result after removing the padding")

    # More detailed explanation:
    # When it returns True (which means no Exception is raised in real-world attack example), it tells us it has a valid padding.
    # We have control on the input (only 2 block CBC). Return True here actually telling the attacker the block ends with 1 of 01,
    # 2 of 02, 3 of 03 ... By knowing the partial actual result, we can obtain the intermediate object! It is just an XOR!
    return True

def CBC_encrypt_secret_str(s_str):
    plain_bytes = bytes(s_str, encoding="utf-8")
    return AES.CBC.encrypt(plain_bytes=plain_bytes, key_bytes=key_bytes, iv=iv_bytes)

# functions for attacking
def block_XOR(block1, block2):
    if len(block1) != len(block2):
        raise ValueError("Both blocks have different sizes")

    return bytearray(b1 ^ b2 for b1, b2 in zip(block1, block2))

def recover_byte_from_oracle(block_bytes, forged_block, target_index, PKCS7_padding_value):
    # IMPORTANT FACT: 2 blocks are enough to form a valid CBC! We don't really need more blocks.
    # Check the reminder graph in attack_on_block() -- ALL blocks are encrypted with the same key!!

    for changing_forged_block in create_all_possible_blocks(forged_block, target_index):
        # bitflipping here -- One of the bytes in changing_block changes from 0-256
        fake_CBC_blocks = changing_forged_block + block_bytes

        # print_bytes_with_description(fake_CBC_blocks, "4")

        if has_valid_padding(fake_CBC_blocks):
            # we make the "ending block" have a valid PKCS7 padding!
            return PKCS7_padding_value ^ changing_forged_block[target_index]

    raise ValueError("Can't form a valid PKCS7 block even after 256 tries? Please debug")

def special_recover_last_byte(block_bytes):
    # This special function is similar to recover_byte_from_oracle(), but have some special condition
    # Inspired from https://www.youtube.com/watch?v=Cb1LO9K3Igg (about 1:25:00) by Filippo Valsorda

    # Problem 1 : We pass forged block(last block) with all 0s, but the plaintext has a valid padding.
    # It means it is a block already ending with 1 of 01, 2 of 02 ... and don't forget the outcome is the same as the intermediate output

    # Problem 2 : We have a correct padding, but we are not sure if it is single 01, or other paddings like 02 02, 03 03 03 ...
    # For example, * 02 01 and * 02 02 are both valid paddings. * 03 03 03 and * 03 03 01 too.
    # We want 01 only.

    # The flow:
    # Problem 1:
    # Pass all 0s as previous block -> Keep changing last byte normally until we find a valid padding -- Problem 2
    #
    # Problem 2:
    # We specify that last byte, then change second last byte -> Try all 256 second last byte -> All correct -> Last byte is correct
    #                                                                                         -> Anything is wrong -> Nope, try again

    forged_block = bytes([0] * 16)

    # Problem 1
    for changing_forged_block in create_all_possible_blocks(forged_block, 15):
        fake_CBC_blocks = changing_forged_block + block_bytes

        if has_valid_padding(fake_CBC_blocks):
            # Problem 2
            for changing_forged_block2 in create_all_possible_blocks(changing_forged_block, 14):
                fake_CBC_blocks2 = changing_forged_block2 + block_bytes

                if not has_valid_padding(fake_CBC_blocks2):
                    break

                # All 1 + 256 cases pass! That must be padding of lonely 1
                return changing_forged_block[15] ^ 1

    raise ValueError("Can't form a valid PKCS7 block in special_recover_last_byte() even after 256 tries? Please debug")

def attack_on_block(block_bytes, previous_block_bytes):
    # Clearly explained on how to attack 1 block https://robertheaton.com/2013/07/29/padding-oracle-attack/

    # Reminder from challenge 16:
    # In CBC decryption, we only needs that cipher block and the block before it to decrypt, assuming the same key.
    #
    #          block 3
    #             |
    #             V
    #   [ AES ECB decrypt(key) ] <--- !!!!!! Main focus here !!!!!
    #             |
    #             V
    # block 2 -> XOR
    #             |
    #             V
    #         plaintext 3
    #
    # This attack recovers the product after decryption but before XOR, just call it intermediate product "i3" for block 3.
    # We recover i3 byte by byte starting from the end of block, with the help of padding verifer and tampered block 2.

    # We keep forging block 2 in this function. However, we need the actual block 2 to obtain plaintext 3.
    # So if we don't know IV, we can't decrypt the first block. (Although we can know the intermediate result of block 0)

    intermediate_result = bytearray([0] * AES_block_size)

    # attack starts here
    for i in range(1, AES_block_size + 1): # 1-16
        # To find the last byte in i3, we want to make plaintext have 01 in last position, so that has_valid_padding() will return True
        # That's the trick we tried in last challenege (CBC bit flipping)
        # wanted_result: (V means whaterver the value is, we don't care)
        #  V  V  V  V
        #  V  V  V  V
        #  V  V  V  V
        #  V  V  V 01

        # Once we got intermediate[15], we can find i3[14] by making plaintext ends with 2 "02"
        # Next wanted_result:
        #  V  V  V  V
        #  V  V  V  V
        #  V  V  V 02
        #  V  V  V 02

        # Assume the last byte in intermediate is 0x69, the forged_block will be ...
        # X X X X
        # X X X X
        # X X X ?
        # X X X 6B

        # 0x6B == 0x02 XOR 0x69
        # This setup ensures last byte after XOR always return 02 (block_XOR())

        # On 3rd run, the last byte in forged will be 0x03 XOR 0x69 == 0x6A.
        # Also, the second last byte in forged also needs to be adjusted accordingly as well.

        # WARNING: One subtle bug may occur, the last byte we recover may not be correct.
        # We expect the plaintext would end with single 01 byte.
        # However, it is possible for it to end with double 02 byte (02, 02).

        # The probability of this occur is ...
        # We fix our 2nd last byte in forged_block to be 0 when the loop begins,
        # so the 2nd last byte in plaintext would also need to be 02. (hopefully is 1/256)
        # And the last byte we try to brute force would also need to be 02. (1/256)

        wanted_result = bytearray([0] * (AES_block_size - i) + [i] * i)
        forged_block = block_XOR(intermediate_result, wanted_result) # setup forged = PADDING XOR intermediate

        # print_bytes_with_description(forged_block, "The forged block when i is {}".format(i))

        # recover bytes backward -- we discover the last byte first in this attack
        target_index = AES_block_size - i
        recovered_byte = recover_byte_from_oracle(block_bytes[:], forged_block[:], target_index, i) if i != 1 else special_recover_last_byte(block_bytes[:])
        intermediate_result[target_index] = recovered_byte

    plain_bytes = block_XOR(intermediate_result, previous_block_bytes)
    return plain_bytes

def create_all_possible_blocks(a, index):
    """
        Given an index and an array a (should be a bytes/bytearray with len of 16 in this challenge),
        create a generator of a copy of that array, everything remains constant except the byte at position "index".

        For example:
        a = [0,1,2,3,4]
        index =  1
        The array can be represented this way: [0,?,2,3,4]

        Then this function will be a generator of [0,0,2,3,4], [0,1,2,3,4], [0,2,2,3,4] ...
    """
    # This function generates all the tampered block for us to attack/bruteforce.
    b_copy = bytearray(a[:])

    for i in range(0,256):
        b_copy[index] = i
        yield b_copy

def find_string_ends_with(found_str):
    length = len(found_str)

    for s in random_secret_strs:
        # last part matches found_str
        if s[-length:] == found_str:
            return s

    raise ValueError("None of the string matches the secret strings, you failed to decrypt?")

def CBC_padding_oracle_attack():
    # Our aim: Decrypt it without key, we can do it with the help of oracle (has_valid_padding())
    cipher_bytes = CBC_encrypt_secret_str(secret_str)
    plain_bytes = bytearray()

    print("Starting the CBC padding oracle attack, may take some time ...")

    # Embarrassing update -- question say that we can have direct access to IV
    # If we don't have IV, we have to skip the 1st block. Then need to guess a secret string
    # from random_secret_strs, and check if any ends with what we found (check the old commit to see the changes LUL)
    for start in range(0, len(cipher_bytes), AES_block_size):
        end = start + AES_block_size

        last_block_start = start - AES_block_size
        last_block_end =  last_block_start + AES_block_size

        block_bytes = cipher_bytes[start: end]

        last_block = iv_bytes if start == 0 else cipher_bytes[last_block_start:last_block_end]

        plain_bytes.extend(attack_on_block(block_bytes, last_block))

    # check result
    plain_bytes = PKCS7_remove_padding(plain_bytes) # we also recover the PKCS7 padding too, so need to remove it ourself
    plain_str = plain_bytes.decode("utf-8")

    # result = find_string_ends_with(plain_str)

    assert plain_str == secret_str
    print("We did it!! Padding Oracle attack works!! Print the string we found and b64 string value now")
    print("What we decrypted: {}".format(plain_str))
    print("Inside that b64 string: {}".format(base64.standard_b64decode(plain_str).decode("utf-8")))

if "__main__" == __name__:
    CBC_padding_oracle_attack()
    print("End of program")
