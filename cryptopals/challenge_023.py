#!/bin/env python
from tools.random_helper import MT19937
import secrets

# use a secure seed to setup MT19937 -- we want to recover its states with its' 624 outputs
seed = secrets.randbits(32)
rand = MT19937(seed)


def create_last_n_1_bits_mask(n):
    """ Return a binary mask of last n bits of 1 """
    if n < 0:
        raise ValueError("n and k cannot be negative number")

    if n == 0:
        return 0

    return (2 << n) - 1

def create_first_n_1_bits_mask(n, k):
    """ Return a binary mask of first n bits of 1, k bits of 0s"""
    if n < 0 or k < 0:
        raise ValueError("n and k cannot be negative number")

    if n == 0:
        return 0

    mask = (2 << n) - 1
    return mask << k

def inverse_xor_right_shift(k, x):
    """Return the original y of k = y ^ (y >> x) operation, from k and x."""

    # print("k is", k)
    # print("x is", x)

    # Small example:
    # y = 1010010 (82)
    # x = 2

    # 1010010  y
    # 0010100 (y >> 2)
    # 1000110  k

    # From k,x to y
    # Round 1:
    # 1?????? y
    # 001???? (y >> 2)
    # 1000110 k
    # ----------------
    # 1110000 bitmask (2+1)=3 of 1s
    # 101???? partial y

    # From our eye we can see the 2nd bit and 3rd bit of y is 0 and 1 respectively, but for computers it is not that easy.
    # We can just treat those ?s as 0s, then use a bitmask to isolate those ? bits.

    # Round 2:
    # 101???? y
    # 00101?? (y >> 2)
    # 1000110 k
    # -----------------
    # 1111100 bitmask of 5
    # 10100?? partial y

    # Round 3:
    # 10100?? y
    # 0010000 (y >> 2)
    # 1000110 k
    # -----------------
    # 1111111 bitmask of 7
    # 1010010 y (completed)

    # handle special cases
    if k == 0 or x == 0:
        # k == 0
        # 0 = y XOR (y >> x), which means y == (y >> x)
        # x must be 0 in this case ...

        # x == 0
        # k = y XOR (y >> 0)
        # k = y XOR y
        # We have no way to get the original y, since all y yields the same result in this case
        raise ValueError("original y can be of any value when k is 0 or x is 0")

    # setup
    original_y = k
    k_size = k.bit_length()  # size of k in terms of bits
    v = 1  # valid amount of 1s in bitmask, start with 1, +x every cycle

    # start the rounds
    while v <= k_size:
        v += x
        v_to_be_used = min(v, k_size)  # v can be much greater than x, if x is very big

        valid_and_mask = create_first_n_1_bits_mask(v_to_be_used, k_size - v_to_be_used)

        # k XOR (y >> x) ... excluding the ??? bits
        original_y = (k ^ (original_y >> x)) & valid_and_mask

    # print("original_y is", original_y)
    return original_y

def inverse_xor_left_shift(k, x, a):
    """Return the original y of k = y ^ ((y << x) & a)operation, from k, a and x."""

    # print("k = {}, x = {}, a = {}".format(k,x,a))

    # Same approach, search bit-by-bit.

    # Example:

    # From k,x,a to y
    # x=2, k=87, a=100
    # ???????? y
    # ??????00 y << 2
    # 01100100 AND
    # ---------------
    # ???????? product of AND
    # ???????? XOR with y
    # ---------------
    # 01010111 k (87)

    # We actually know the last 2(x) bits of product of AND is 0, since last bit of y << 2 must be 0.
    # Also, we write y in another way...
    # abcdefgh y
    # cdefgh00 y << 2
    # 01100100 AND
    # ----------------
    # ??????00
    # abcdefgh XOR
    # ----------------
    # 01010111 k (87)

    # We actually knows bit g and h!
    # abcdef11 y
    # cdef1100 y << 2
    # 01100100 AND
    # ----------------
    # ????0100
    # abcdef11 XOR
    # ----------------
    # 01010111 k (87)

    # We can repeat and find y eventually.

    if x == 0:
        # When x is 0 ...
        # abcde y    |
        # ????? AND  |
        # ---------- |
        # ????? r    | <-
        # abcde XOR  |
        # ---------- |
        # opqrs k    |

        # x == 0 is problematic actually ...
        # Truth table, K is the output this time
        # y | A | K
        # 0 | 0 | 0
        # 0 | 1 | 0 <-
        # 1 | 0 | 1
        # 1 | 1 | 0 <-
        # For the same K(0) if A is (1), y can be 0 or 1!! This is not one-to-one!!
        raise ValueError("if x is 0, we can't recover y with 100% certainty")

    if a == 0:
        # It is just (0 XOR y) == k, y == k
        return k

    if k == 0:
        # We can handle this without treating it as special case actually, but it can save us some looping
        # Assume x is 1 or above

        # ???0 y << x |
        # ???? AND    |
        # ---------   |
        # ???0 r      |
        # ???? XOR y  |
        # ---------   |
        # 0000 k      |

        # So last bit of y must be 0, then ...

        # ??00 y << x |
        # ???? AND    |
        # ---------   |
        # ??00 r      |
        # ???0 XOR y  |
        # ---------   |
        # 0000 k      |

        # ... All bits of y must be 0

        # Another way to prove:
        # (y << x) AND a == y, otherwise it cannot yield 0 after XOR
        # For simplicity, assume a is all 1s already (best case), so (y << x) == y (if k == 0)
        # if y contains any 1 bit, (y << x) cannot be the same as y, so y must be 0.
        return 0

    # setup
    original_y = 0
    and_bitmask_size = 0

    # The end condition is tricky -- k can be very small while y is very big (but not the inverse)
    # Also, a can be of any size too ... so we just use the larger one
    larger_bit_size = max(a.bit_length(), k.bit_length())

    while and_bitmask_size <= larger_bit_size:
        and_bitmask_size += x
        and_bitmask = create_last_n_1_bits_mask(and_bitmask_size)

        original_y = (k ^ ((original_y << x)& a) ) & and_bitmask
        # print("original_y is {}, when bit mask size is {}".format(original_y, and_bitmask_size))

    # print("original_y is {}".format(original_y))

    return original_y

def untemper(y):
    # inverse of the original genrand_int32 function()

    # y ^= (y >> 11)
    # y ^= (y << 7) & 0x9d2c5680
    # y ^= (y << 15) & 0xefc60000
    # y ^= (y >> 18)

    y = inverse_xor_right_shift(y, 18)
    y = inverse_xor_left_shift(y, 15, 0xefc60000)
    y = inverse_xor_left_shift(y, 7, 0x9d2c5680)
    y = inverse_xor_right_shift(y, 11)

    return y

def get_full_cycle_output():
    lst = []

    # NOTE: If we give each output a sequence number, this batch is from 0-623.
    # MT19937 updates its internal states (mt[]) after generating 624 numbers (the twist() function).

    # If we are given something in middle (not 0 mod 624), like 1, or 326,
    # the set will be 1-624, 326-949... Then we need some extra work to identify
    # the set is belong to 2 different batches... The challenge doesn't require us to handle this case now.
    for i in range(624):
        lst.append(rand.genrand_int32())
    return lst

def crack_MT19937_from_output():
    output_set = get_full_cycle_output()

    states = []
    for o in output_set:
        states.append(untemper(o))

    another_rand = MT19937()

    another_rand.copy_state_from_array(states)

    # test for another 625 numbers
    for k in range(625):
        if another_rand.genrand_int32() != rand.genrand_int32():
            raise ValueError("Different 32-bit number output -- failed to clone the MT19937?")

    print("We copied MT19937 correctly from its output!!!")
    return True

def create_xor_right_shift_case(y, x):
    # see if our function can get reverse the XOR right shift
    # print("testing y:{}, x:{}".format(y,x))
    assert inverse_xor_right_shift(y ^ (y >> x) , x) == y

def test_inverse_xor_right_shift():
    print("Running test cases for inverse XOR right shift")

    create_xor_right_shift_case(23457654, 7)
    create_xor_right_shift_case(34509802, 3)
    create_xor_right_shift_case(16745, 2)

    # y or x == 0 is invalid case, check comments in inverse_xor_right_shift() for explanation
    for y in range(1, 1025):
        for x in range (1,11):
            create_xor_right_shift_case(y,x)

    print("Inverse XOR right shift function seems correct")

def create_xor_left_shift_case(y, x, a):
    # see if our function can get reverse the XOR left shift
    # print("k is {}, expected y is {}, x = {}, a = {}".format((y ^ ((y << x) & a)), y, x , a))
    assert inverse_xor_left_shift(y ^ ((y << x) & a) , x, a) == y

def test_inverse_xor_left_shift():
    print("Running test cases for inverse XOR left shift")

    create_xor_left_shift_case(5, 2, 4)
    create_xor_left_shift_case(1, 1, 14)
    create_xor_left_shift_case(1, 3, 14)
    create_xor_left_shift_case(19, 2, 100)

    for y in range(513):
        for x in range(1,12): # x can't be 0, check comments in inverse_xor_left_shift()
            for a in range(1025):
                create_xor_left_shift_case(y, x, a)

    print("Inverse XOR left shift function seems correct")

if "__main__" == __name__:
    test_inverse_xor_right_shift()
    test_inverse_xor_left_shift()

    crack_MT19937_from_output()
    # Last question from challenge... again, no one tells me if my answer is correct or not.

    # How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?

    # After a bit thinking and cheating -- searching for wiki (https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator),
    # the answer is ...
    # 1. Make the untemper() impossble by some crypto setup, like using encryption and/or hashing
    # 2. Simliar to above, use some hard questions (like discrete log/ factorization) to setup internal states,
    # of course the private key cannot be retrieved/reverse-engineered by any means
    # 3. (I actually copy this from wiki) Even if the internal states are exposed, make it impossble to predict/generate next output easily ...
    # but I don't know how actually. Maybe answer 1/2 is the implementation of this idea.

    # If each tempered output are hashed, then ... we have to attack the hash function to attack this PRNG.
    # If it is not using salt, we can create a 2^32 table to match the each 32 bit output to a hashed output to break it ... Still, 2^32 is big, but seems
    # not impossible in near future. (Haven't tried rainbow table or something like that yet)
    # However, I am not sure if the output would pass the random test or not in this hash setup.

    print("End of program")