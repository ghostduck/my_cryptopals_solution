import base64


def read_hex_encoded_text_file(location):
    # return an arrays of immutable bytes array(bytes), each cell contains a line of bytes

    # This function reads tons of text of bytes like "6969690E1F03..."
    with open(location, "r") as file_source:
        str_array = list(file_source)

        return list(bytes.fromhex(line.strip()) for line in str_array)

def read_base64_encoded_text_file(location):
    # get base64 string from file, return as single byte array
    with open(location, "r") as file_source:
        fileStr = file_source.read()
    return base64.standard_b64decode(fileStr)

