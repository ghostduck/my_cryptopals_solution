# mt19937
# Original code: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
# Python code referenced: https://github.com/bmurray7/mersenne-twister-examples/blob/master/python-mersenne-twister.py

from itertools import cycle

# constants
N = 624
M = 397
MATRIX_A = 0x9908b0df   # constant vector a
UPPER_MASK = 0x80000000 # most significant w-r bits
LOWER_MASK = 0x7fffffff # least significant r bits

# helper functions
def _int32(x):
    return int(x & 0xffffffff)

def value_from_key_array(key):
    source = cycle(enumerate(key))

    while True:
        i,v = next(source)
        yield i + v  # same as (init_key[j] + j) in the original C code


class MT19937(object):
    def __init__(self, seed=None):
        self.setup()
        if seed is not None:
            self.init_genrand(s)
        else:
            print("WARNING: Seed is not provided. Please ensure you setup with init_genrand(seed) or init_by_array(array)")

    def setup(self):
        self._mt = [0] * N
        self._mti = N+1  # index of mt, N+1 means uninitialized
        self._mag01 = [0, MATRIX_A]

    def init_genrand(self, s):
        # initializes mt[N] with a seed
        self._mt[0]= _int32(s)

        for i in range(1, N):
            previous = self._mt[i-1]
            self._mt[i] = _int32(
                (1812433253 * (previous ^ (previous >> 30)) + i)
            )

        # same result as the C code, in C code it updates mti in for loop
        self._mti = N

    def init_by_array(self, init_key):
        self.init_genrand(19650218)  # set up seed with birthday first LUL

        key_source =  value_from_key_array(init_key)
        k = max(N, len(init_key))  # we want at least N(624), if key is not long enough

        i = 1

        for m in range(k): # cycle 624 (N) times
            previous = self._mt[i-1]
            self._mt[i] = _int32(
                (self._mt[i] ^ ((previous ^ (previous >> 30)) * 1664525)) + next(key_source)
            )

            i += 1
            if (i >= N):
                self._mt[0] = self._mt[N-1]
                i = 1  # make sure it is from 1 to N-1(623)

        # second loop, note that i continues from the previous loop
        for m in range(N-1):  # cycle 623 times (N-1)
            previous = self._mt[i-1]

            self._mt[i] = _int32(
                (self._mt[i] ^ ((previous ^ (previous >> 30)) * 1566083941)) - i
            )

            # need to copy these wrap back code, FeelsBadMan
            i += 1
            if (i >= N):
                self._mt[0] = self._mt[N-1]
                i = 1  # make sure it is from 1 to N-1(623)

        self._mt[0] = UPPER_MASK

    def genrand_int32(self):
        if self._mti >= N:
            self.twist()

        y = self._mt[self._mti]
        self._mti += 1

        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)

        return _int32(y)

    def twist(self):
        mag01 = [0, MATRIX_A]

        if self._mti == N+1:
            # if init_genrand() or init_by_array() has not been called
            # use this default seed to setup
            self.init_genrand(5489)

        for i in range(N):  # 0 - 623
            # don't know why original C code didn't use mod, but use 3 for loop with different indices instead
            current_first_bit = self._mt[i] & UPPER_MASK
            next_remaining_bits = self._mt[(i+1)%N] & LOWER_MASK

            y = current_first_bit | next_remaining_bits

            self._mt[i] = self._mt[(i+M)%N] ^ (y >> 1) ^ mag01[y & 1]  # [0] = [0 + 397] ... wrap if >= 624

        self._mti = 0
