# http://cryptopals.com/sets/1/challenges/4

from collections import defaultdict
import string

def setScore(d, inter_dict):
    for letter, score in inter_dict.items():
        d[letter.upper()] = score
        d[letter.lower()] = score

def setupDict():
    inter_dict = dict()

    for c in string.ascii_lowercase:
      inter_dict[c] = 1
    inter_dict[' '] = 1.5

    inter_dict['e'] = 1.9
    inter_dict['t'] = 1.7
    inter_dict['a'] = 1.7
    inter_dict['o'] = 1.7
    inter_dict['i'] = 1.6
    inter_dict['n'] = 1.6

    inter_dict['s'] = 1.6
    inter_dict['h'] = 1.5
    inter_dict['r'] = 1.5
    inter_dict['d'] = 1.4
    inter_dict['l'] = 1.4
    inter_dict['u'] = 1.4

    return inter_dict

def decryptXORinFile():

    # setup, stricter scheme this time -- "incorrect" characters give negative points
    score_dict = defaultdict(lambda : -1)
    inter_dict = setupDict()
    setScore(score_dict, inter_dict)

    # contains tuble of (score, byte)
    total_list = []

    # WTF, the possible key is a nubmer in this set ...
    letter_set = string.printable

    # for outputing
    max = ('keyletter', 0, 'original encoded string' ,'output')

    # each line has 60 characters, 30 bytes. One of the line is encrypted by single character XOR
    with open("4.txt", "r") as file_source:
        str_array = list(file_source)

    for line in str_array:
        line = line.strip()
        line_byte = bytearray.fromhex(line)
        byte_length = len(line_byte)

        for k in letter_set:
            # create repeated letter
            k_str = k * byte_length

            total_score = 0

            # XOR, then count
            key_byte = bytearray(k_str, 'utf-8')
            ba_xor = bytearray()

            for b1,b2 in zip(line_byte, key_byte):
                xor_byte = b1 ^ b2

                letter = chr(xor_byte)
                total_score += score_dict[letter]

                ba_xor.append(xor_byte)

            if total_score > max[1]:
                max = (k, total_score, line, ba_xor)

            # Just for debugging -- correct result should have more than 30 points
            # if total_score > 28:
                # total_list.append((k, total_score, ba_xor))

    # looping finished, see result
    key, score, source_line, xor_out = max
    xor_out = xor_out.decode('utf-8')

    output_t = (key, score, source_line, xor_out)
    print(output_t)

    # total_list.sort(key=lambda x:x[1], reverse=True)
    # print(total_list)

# from tools.crypto_helper import VigenereBreaker
# def decryptXORinFile2():
    # with open("4.txt", "r") as file_source:
        # str_array = list(file_source)

    # best_score = ('key', 0, 'decrypted bytes')
    # vb = VigenereBreaker()

    # for line in str_array:
        # line = line.strip()
        # line_byte = bytearray.fromhex(line)
        # output = vb.processEncryptedBytes(line_byte, string.printable)
        # if output[1] > best_score[1]:
            # best_score = output

    # print(best_score)
    # print(best_score[2].decode('utf-8'))

if "__main__" == __name__:
    decryptXORinFile()
    #decryptXORinFile2()
    print("End of program")
