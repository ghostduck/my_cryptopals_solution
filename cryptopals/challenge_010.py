from tools.crypto_helper import AES
from tools.file_helper import read_base64_encoded_text_file

def CBC_decrypt():
    file_bytes = read_base64_encoded_text_file("10.txt")
    key_bytes = bytes("YELLOW SUBMARINE", "utf-8")
    iv = bytes([0]*16)

    plain_bytes = AES.CBC.decrypt(cipher_bytes=file_bytes, key_bytes=key_bytes, iv=iv)
    # same lyrics as in challenge 7 !!
    print(plain_bytes.decode("utf-8"))

if __name__ == "__main__":
    CBC_decrypt()
    print("End of program")
