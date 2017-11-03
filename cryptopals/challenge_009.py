from tools.crypto_helper import PKCS7_add_padding, PKCS7_remove_padding

def test_PKCS7_padding():
    text = "YELLOW SUBMARINE"
    text_byte = bytearray(text, "utf-8")

    padded_byte = PKCS7_add_padding(text_byte, block_size=20)

    for i,b in enumerate(text_byte):
        assert padded_byte[i] == b

    # check for padding bytes
        assert padded_byte[16] == padded_byte[17] == padded_byte[18] == padded_byte[19] == 0x04

    assert PKCS7_remove_padding(padded_byte) == text_byte

    full_block = bytes([1,2,3,4,5])

    # should pad 5,5,5,5,5 for full_block when block_size = 5
    padded_full_byte = PKCS7_add_padding(full_block, 5)

    # original block is unchnaged ... for current design right now
    assert full_block == bytes([1,2,3,4,5])
    assert padded_full_byte == bytes([1,2,3,4,5,5,5,5,5,5])

    assert PKCS7_remove_padding(padded_full_byte) == full_block

    # Fail case - strict checking on remove padding of invalid bytes
    try:
        invalid_pkcs7_padding_bytes = bytes([5,4,3,2,0])
        PKCS7_remove_padding(invalid_pkcs7_padding_bytes)
    except ValueError as e:
        print(e)
        print("Fail case passed - invalid bytes failed on remove padding")

    print("pkcs7 testing completed, SeemsGood")

if "__main__" == __name__:
    test_PKCS7_padding()
    print("End of program")
