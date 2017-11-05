from tools.crypto_helper import AES
from tools.file_helper import read_base64_encoded_text_file

def check_CBC():
    file_bytes = read_base64_encoded_text_file("10.txt")
    key_bytes = bytes("YELLOW SUBMARINE", "utf-8")
    iv = bytes([0]*16)

    plain_bytes = AES.CBC.decrypt(cipher_bytes=file_bytes, key_bytes=key_bytes, iv=iv)
    # same lyrics as in challenge 7 !
    print(plain_bytes.decode("utf-8"))

if __name__ == "__main__":
    check_CBC()
    print("End of program")
