from tools.file_helper import read_hex_encoded_text_file
from tools.crypto_helper import AES_decrypt

def grouped(iterable, n):
    "s -> (s0,s1,s2,...sn-1), (sn,sn+1,sn+2,...s2n-1), (s2n,s2n+1,s2n+2,...s3n-1), ..."
    return zip(*[iter(iterable)]*n)

def decrypt_AES_line(line):
    # d880619740a8a19b7840a8a31c810a3d
    print(line)
    line_byte = bytes.fromhex(line.strip())
    keyBytes = bytearray("YELLOW SUBMARINE", "utf-8")

    aes_blocks = grouped(line_byte, 16)
    msg = []

    for b in aes_blocks:
        cipher_bytes = bytes(b)
        plain_bytes = AES_decrypt(keyBytes, cipher_bytes)

        plaintext = plain_bytes.decode("utf-8")
        print(plaintext)

def count_dup_in_file(str_array):
    # Although we should work with bytes for crypto challenges, I think we need to work with strings this time.
    # Because str is hashable (actually bytes also works too, but the transformation is not needed at all), dict for counting can be used

    # How to find the ECB line?
    #
    # Each line has 320 characters, 160 bytes. Each 16 bytes is a possible output of AES.
    # Try to count every 32 letters (16 bytes), see if we can find any duplications

    # The biggest hint is same plaintext will give same ciphertext in ECB, so we try to find duplicates in 1 line.
    # We have no way to break AES without knowing a key

    multi_count = {}

    for line_number, line in enumerate(str_array, start=1):
        # each 32 letters (16 bytes) in a line (should have 10 groups)
        aes_blocks = grouped(line, 32)

        line_block_dup_count = {}

        for b in aes_blocks:
            block_str = "".join(b)

            if block_str in line_block_dup_count:
                line_block_dup_count[block_str] += 1
            else:
                line_block_dup_count[block_str] = 1

        # process line_block_dup_count by add duplicated hex strings (entries with value > 1) to multi_count
        for k,v in line_block_dup_count.items():
            if v > 1:
                multi_count[k] = (v, line_number)

    print(multi_count)
    return multi_count

if "__main__" == __name__:
    #bytes_per_line = read_hex_encoded_text_file("8.txt") # not used -- load bytes from file

    with open("8.txt", "r") as file_source:
        str_array = list(file_source)

    count_dup_in_file(str_array)

    # Find that "08649af70dc06f4fd5d2d69c744cd283" occured 4 times in line 133
    # Try to decrypt it with "YELLOW SUBMARINE" ... but it is not the key
    # decrypt_AES_line(str_array[132])

    print("End of program")

