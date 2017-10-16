# http://cryptopals.com/sets/1/challenges/3

from collections import defaultdict
import string

def setScore(d, inter_dict):
    for letter, score in inter_dict.items():
        d[letter.upper()] = score
        d[letter.lower()] = score

def setupDict():
    # This question tricks your with 'e', actually contains 1 'e' in correct string
    # You need to set the weighing correctly so that it won't brute force the crap with many 'e's

    # Or just try to see if decryped text is in letters/space or not, it was bytes originally
    inter_dict = dict()
    for c in string.ascii_lowercase: # uppercase will be handled in setScore()
      inter_dict[c] = 3
    inter_dict[' '] = 1

    # This works too
    # inter_dict = {
        # 'e' : 10,
        # 't' : 9,
        # 'a' : 9,
        # 'o' : 9,
        # 'i' : 8,
        # 'n' : 8,
        # ' ' : 5   # if you know this contains space, space scores helps A LOT
    # }

    # wrong score dict example:
    # inter_dict = {
        # 'e' : 3,
        # 't' : 2,
        # 'a' : 2,
        # 'o' : 2,
        # 'i' : 1,
        # 'n' : 1,
    # }

    return inter_dict

def decryptXOR():

    byte_str  = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    #  "ETAOIN SHRDLU"
    # byte1 is XORed with a single character repeating itself
    b = bytearray.fromhex(byte_str)
    l = len(b)

    score_dict = defaultdict(lambda : 0)
    inter_dict = setupDict()
    setScore(score_dict, inter_dict)

    # store key to total score (int)
    result_dict = dict()

    # brute force time
    max = ('keyletter', 0, 'output')

    letter_set = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    #letter_set = 'abcdefghijklmnopqrstuvwxyz'
    #letter_set = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for k in letter_set:
        # create repeated letter
        k_str = k * l

        total_score = 0

        #print(k_str)

        # XOR, then count
        b2 = bytearray(k_str, 'utf-8')
        ba_xor = bytearray()

        for b1,b2 in zip(b,b2):
            xor_byte = b1 ^ b2

            letter = chr(xor_byte)
            total_score += score_dict[letter]

            ba_xor.append(xor_byte)

        result_dict[k] = total_score

        if total_score > max[1]:
            max = (k, total_score, ba_xor.decode('utf-8'))

    # looping finished, see result
    print(max)
    result_dict.sort()
    print(result_dict)


if "__main__" == __name__:
    decryptXOR()
    print("End of program")
