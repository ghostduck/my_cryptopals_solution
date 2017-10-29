# Reference: http://www.samiam.org/galois.html

gf_2n_mul_inv_result = [
0x00, 0x01, 0x8D, 0xF6, 0xCB, 0x52, 0x7B, 0xD1, 0xE8, 0x4F, 0x29, 0xC0, 0xB0, 0xE1, 0xE5, 0xC7,
0x74, 0xB4, 0xAA, 0x4B, 0x99, 0x2B, 0x60, 0x5F, 0x58, 0x3F, 0xFD, 0xCC, 0xFF, 0x40, 0xEE, 0xB2,
0x3A, 0x6E, 0x5A, 0xF1, 0x55, 0x4D, 0xA8, 0xC9, 0xC1, 0x0A, 0x98, 0x15, 0x30, 0x44, 0xA2, 0xC2,
0x2C, 0x45, 0x92, 0x6C, 0xF3, 0x39, 0x66, 0x42, 0xF2, 0x35, 0x20, 0x6F, 0x77, 0xBB, 0x59, 0x19,
0x1D, 0xFE, 0x37, 0x67, 0x2D, 0x31, 0xF5, 0x69, 0xA7, 0x64, 0xAB, 0x13, 0x54, 0x25, 0xE9, 0x09,
0xED, 0x5C, 0x05, 0xCA, 0x4C, 0x24, 0x87, 0xBF, 0x18, 0x3E, 0x22, 0xF0, 0x51, 0xEC, 0x61, 0x17,
0x16, 0x5E, 0xAF, 0xD3, 0x49, 0xA6, 0x36, 0x43, 0xF4, 0x47, 0x91, 0xDF, 0x33, 0x93, 0x21, 0x3B,
0x79, 0xB7, 0x97, 0x85, 0x10, 0xB5, 0xBA, 0x3C, 0xB6, 0x70, 0xD0, 0x06, 0xA1, 0xFA, 0x81, 0x82,
0x83, 0x7E, 0x7F, 0x80, 0x96, 0x73, 0xBE, 0x56, 0x9B, 0x9E, 0x95, 0xD9, 0xF7, 0x02, 0xB9, 0xA4,
0xDE, 0x6A, 0x32, 0x6D, 0xD8, 0x8A, 0x84, 0x72, 0x2A, 0x14, 0x9F, 0x88, 0xF9, 0xDC, 0x89, 0x9A,
0xFB, 0x7C, 0x2E, 0xC3, 0x8F, 0xB8, 0x65, 0x48, 0x26, 0xC8, 0x12, 0x4A, 0xCE, 0xE7, 0xD2, 0x62,
0x0C, 0xE0, 0x1F, 0xEF, 0x11, 0x75, 0x78, 0x71, 0xA5, 0x8E, 0x76, 0x3D, 0xBD, 0xBC, 0x86, 0x57,
0x0B, 0x28, 0x2F, 0xA3, 0xDA, 0xD4, 0xE4, 0x0F, 0xA9, 0x27, 0x53, 0x04, 0x1B, 0xFC, 0xAC, 0xE6,
0x7A, 0x07, 0xAE, 0x63, 0xC5, 0xDB, 0xE2, 0xEA, 0x94, 0x8B, 0xC4, 0xD5, 0x9D, 0xF8, 0x90, 0x6B,
0xB1, 0x0D, 0xD6, 0xEB, 0xC6, 0x0E, 0xCF, 0xAD, 0x08, 0x4E, 0xD7, 0xE3, 0x5D, 0x50, 0x1E, 0xB3,
0x5B, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8C, 0xDD, 0x9C, 0x7D, 0xA0, 0xCD, 0x1A, 0x41, 0x1C
]


# 3^k in GF(2n), we know that 3 is a generator in GF(2^n)
gf_2n_expo_table_of_3 = [
0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35,
0x5F, 0xE1, 0x38, 0x48, 0xD8, 0x73, 0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA,
0xE5, 0x34, 0x5C, 0xE4, 0x37, 0x59, 0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70, 0x90, 0xAB, 0xE6, 0x31,
0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x4F, 0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD,
0x4C, 0xD4, 0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08, 0x18, 0x28, 0x78, 0x88,
0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F, 0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76, 0x9A,
0xB5, 0xC4, 0x57, 0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6, 0x61, 0xA3,
0xFE, 0x19, 0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F, 0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0,
0xFB, 0x16, 0x3A, 0x4E, 0xD2, 0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F, 0x41,
0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0, 0x5B, 0xED, 0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75,
0x9F, 0xBA, 0xD5, 0x64, 0xAC, 0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC, 0xDF, 0x7A, 0x8E, 0x89, 0x80,
0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F, 0xB1, 0xC8, 0x43, 0xC5, 0x54,
0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA,
0x45, 0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42, 0xC6, 0x51, 0xF3, 0x0E,
0x12, 0x36, 0x5A, 0xEE, 0x29, 0x7B, 0x8D, 0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17,
0x39, 0x4B, 0xDD, 0x7C, 0x84, 0x97, 0xA2, 0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7, 0x52, 0xF6, 0x01
]

# inverse of gf_2n_expo_table_of_3
# Given an output value, say 0x4D. We want to find k in (3^k == 0x4D). log[0x4D] will get the result (0x46)
# 3^0x46 == 0x4D, from expo table
gf_2n_log_table_of_3 = [
0x00, 0xFF, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B, 0x68, 0x33, 0xEE, 0xDF, 0x03,
0x64, 0x04, 0xE0, 0x0E, 0x34, 0x8D, 0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1,
0x7D, 0xC2, 0x1D, 0xB5, 0xF9, 0xB9, 0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72, 0x9A, 0xC9, 0x09, 0x78,
0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1, 0x24, 0x12, 0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E,
0x96, 0x8F, 0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1, 0x40, 0x46, 0x83, 0x38,
0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62, 0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91, 0x10,
0x7E, 0x6E, 0x48, 0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85, 0x3D, 0xBA,
0x2B, 0x79, 0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E, 0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57,
0xAF, 0x58, 0xA8, 0x50, 0xF4, 0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD, 0xE8,
0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5, 0x59, 0xCB, 0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0,
0x7F, 0x0C, 0xF6, 0x6F, 0x17, 0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F, 0x2D, 0xA4, 0x76, 0x7B, 0xB7,
0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1, 0x6C, 0xAA, 0x55, 0x29, 0x9D,
0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE, 0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1,
0x53, 0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D, 0x56, 0xF2, 0xD3, 0xAB,
0x44, 0x11, 0x92, 0xD9, 0x23, 0x20, 0x2E, 0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5,
0x67, 0x4A, 0xED, 0xDE, 0xC5, 0x31, 0xFE, 0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0, 0xF7, 0x70, 0x07
]

def gf_2n_mul(a,b):
    product = 0

    for c in range(8): # force to loop 8 times, more secure against timing-attack
    #while a != 0 and b != 0: # earlier exit

        if b & 1 == 1:
            # add a to product in GF(2^n)
            product ^= a

        # (a * b) == (2a * 0.5b)
        # don't need to worry about b got trancated
        # Example: n x 3
        # n x 3 is (2n + n), the last bit is added to product, then b got reduced to 2, then n is doubled
        a <<= 1
        if a >= 256:
            # 0x11B is the irreducible reducing polynomial for GF(2^n) in AES
            a ^= 0x11B
        b >>= 1

    return product

def gf_2n_mul_faster(a,b):
    # Shamelessly copy from http://www.samiam.org/galois.html
    # Idea: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    # a*b == g^log(ab) == g^(log(a)+log(b))
    #
    # Example: 5x8
    #
    # Using 3 as generator, 5 is 3^2
    #                       8 is 3^75, which is 3^0x4B
    #
    # 5x8 == 3^(2+75) == 3^77 (0x4D)
    #
    # Then we can use lookup table to get 3^77, expo[0x4D], which is 0x28

    # Larger example: 246x119 (0xF6 x 0x77)
    # From log table, 0xF6 is 3^0xFE
    #                 0x77 is 3^0xCA
    #
    # 246x119 == 3^(FE+CA mod 255) == 3^0xC9 == 3^201
    #
    # which is 0x2D, 45

    z = 0
    s = gf_2n_log_table_of_3[a] + gf_2n_log_table_of_3[b]
    # Why 255 but not 256? Because expo_table[255] == expo_table[0] == 1, the cycle ends at [254] (the 255th element)

    s %= 255

    # the result is here
    s = gf_2n_expo_table_of_3[s]
    q = s

    # These if else is used against timing-attack
    if a == 0:
        s = z
    else:
        s = q

    if b == 0:
        s = z
    else:
        q = z

    return s


def generate_gf_2n_mul_inv_result_bruteforce():
    # cycle 255 * 255 times to get everything
    result = [None] * 256
    result[0] = 0
    result[1] = 1

    # loop_gen = ((i,k) for i in range(2,256) for k in range(2,256))

    # for i,k in loop_gen:
        # if result[k] is not None and result [i] is not None:
        # if gf_2n_mul(i,k) == 1:
            # result[i] = k
            # result[k] = i

    # slightly optimized bruteforce
    unused = list(range(2,256))
    while len(unused) != 0:
        i = unused[0]
        for k in unused[1:]:
            if gf_2n_mul(i,k) == 1:
                result[i] = k
                result[k] = i

                unused.remove(k)
                unused.remove(i)
                break


    print(", ".join(format(k, "#04X") for k in result))
    return result

def generate_gf_2n_expo_table_of_3():
    result = [None] * 256
    result[0] = 1 # g^0 == 1 for all generators

    multiplier = 3

    for i in range(1,256):
        result[i] = gf_2n_mul(result[i-1], multiplier)

    print(", ".join(format(k, "#04X") for k in result))
    return result

def generate_gf_2n_log_table_of_3():
    result = [None] * 256

    # The index is correct -- we know 3^255 is 1, which is the same as 3^0, we stop at 254
    for i,k in enumerate(gf_2n_expo_table_of_3[:255]):
        result[k] = i

    result[0] = 0
    result[1] = 0xFF

    print("gf_2n_log_table_of_3 = [")
    print(", ".join(format(k, "#04X") for k in result))
    print("]")
    return result


def simplified_affine_transformation(b):
    # use XOR instead of matrix since they are all in GF(2)
    # rename matrix to byte here

    matrix_in_byte = [
        0b10001111,
        0b11000111,
        0b11100011,
        0b11110001,
        0b11111000,
        0b01111100,
        0b00111110,
        0b00011111,
    ]

    byte_to_add = 0b01100011

    # multiplication
    # 0 x 0 = 0
    # 0 x 1 = 0
    # 1 x 0 = 0
    # 1 x 1 = 1
    # It is (b AND matrix_in_byte[0]) XOR (b AND matrix_in_byte[1]) ...
    product = (b & matrix_in_byte[0]) ^ \
        (b & matrix_in_byte[1]) ^ \
        (b & matrix_in_byte[2]) ^ \
        (b & matrix_in_byte[3]) ^ \
        (b & matrix_in_byte[4]) ^ \
        (b & matrix_in_byte[5]) ^ \
        (b & matrix_in_byte[6]) ^ \
        (b & matrix_in_byte[7])

    # last step: Add to byte_to_add (XOR)
    return product ^ byte_to_add

#test = simplified_affine_transformation(0)
#affine_transformation([0,0,0,0,0,0,0,0])
#print(test, test == 0x63)

print(gf_2n_mul(3,7)) # 9
print(gf_2n_mul(7,3)) # 9
print(gf_2n_mul(0x53,0xCA)) # 1
#generate_gf_2n_log_table_of_3()
print(gf_2n_mul_faster(3,7) == gf_2n_mul_faster(7,3) == gf_2n_mul(3,7) == gf_2n_mul(7,3))
print(gf_2n_mul_faster(0x53,0xCA) == gf_2n_mul_faster(0xCA,0x53) == gf_2n_mul(0x53,0xCA) == gf_2n_mul(0xCA,0x53))
print(gf_2n_mul_faster(0xF6,0x77))
print(gf_2n_mul(0xF6,0x77))
input("")

# exp_of_e5[0xfe] == 0x0e # e5^fe == 0x0e
# log_of_e5[0x0e] == 0xfe # inverse of exp_of_e5

# exp_of_e5[0x01] == 0xe5
# log_of_e5[0xe5] == 0x01 # in order to get e5 from generator, we only need to multiply once


