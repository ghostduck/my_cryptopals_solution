from collections import defaultdict
from itertools import cycle
import string

class VigenereBreaker(object):
    def __init__(self, amout_max_result = 5):
        self.AMOUNT_MAX_RESULT = amout_max_result
        self.result_record = []
        
        # -1 default dict aims to punish unprintable strings
        self.score_dict = defaultdict(lambda : -1)
        self.setScore(self.setupDict())

    # about setScore() and setupDict -- they can have different locale options on different plaintext
    # currently just ASCII/English words    
    def setupDict(self):
        inter_dict = dict()

        for c in string.ascii_lowercase:
          inter_dict[c] = 1
        
        # adjust weighting here, I could have make a JSON of weighting and load it instead
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
        
        # can add other letters for weighted scores, but I am too lazy

        return inter_dict
        
    def setScore(self, inter_dict):
        for letter, score in inter_dict.items():
            self.score_dict[letter.upper()] = score
            self.score_dict[letter.lower()] = score

    # actually try to solve the XOR with repeated single bytes problem only
    # return a tuple showing of (best_key_string, score, decrypted_bytes)  
    def processEncryptedBytes(self, encrypted_bytes, possible_keys):
        # cleanup
        self.result_record.clear()
        
        # tuple should be (best_key_string, score, that_decrypted_bytes)
        best_result = ('best_key_string', 0, [] )
        
        for k in possible_keys:
            # create a stream of repeated letter bytes
            keystrBytes = bytearray(k, "utf-8")
            keyBytesStream = cycle(keystrBytes)
            
            total_score = 0
            ba_xor = bytearray()
        
            for b in encrypted_bytes:
                xor_byte = b ^ next(keyBytesStream)

                letter = chr(xor_byte)
                total_score += self.score_dict[letter]

                ba_xor.append(xor_byte)

            result = (k, total_score, ba_xor)
            # try to add result to result_record
            self.__check_add_result_record(result)

            if total_score > best_result[1]:
                best_result = result

        return best_result
        
    # debugging function, should only be called after processEncryptedBytes()
    # return the best 5 results of decryption attempt
    def showBestChoices(self):
        return self.result_record
        
    def __check_add_result_record(self, result):
        LIMIT = self.AMOUNT_MAX_RESULT
        if len(self.result_record) < LIMIT:
            self.__add_and_sort_result_record(result)
        else:
            # Sorted Array already full, check need to replace or not
            if result[1] > self.result_record[LIMIT -1][1]:
                # Better score found
                self.__add_and_sort_result_record(result)
                
    def __add_and_sort_result_record(self, result):
        self.result_record.append(result)
        # Highest score at [0]
        self.result_record.sort(key=lambda x:x[1], reverse=True)