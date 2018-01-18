#!/bin/env python
from tools.random_helper import MT19937

# These results are obtained by compiling and running the C code (check mt19937.c for reference)
# I print mt[] after init_by_array() to obtain the state
path_to_random_helper = "tools/random_helper/test_data/{}"
state_after_setup_file_path = path_to_random_helper.format("mt19937_state_after_init.txt")
the_1000_num_gen_file_path = path_to_random_helper.format("mt19937_sample_output.txt")
state_after_gen_100_file_path = path_to_random_helper.format("mt19937_state_after_1000_gen.txt")


def get_int_list_from_file(path):
    a = []

    with open(path, "r") as source:
        for line in source:
            nums_str = line.split()
            nums = [int(n) for n in nums_str]
            a.extend(nums)

    return a

def test_MT19937():
    # Test 3 things. If all pass, then the MT19937 implementation should be correct
    init_array = [0x123, 0x234, 0x345, 0x456]  # same array as in C code

    r = MT19937()
    r.init_by_array(init_array)

    # Test 1: state after init_array()
    state_after_init = get_int_list_from_file(state_after_setup_file_path)
    assert r._mt == state_after_init

    # Test 2: generated 1000 intergers, check if they are same
    the_1000_ints = []
    for i in range(1000):
        the_1000_ints.append(r.genrand_int32())

    the_1000_ints_from_reference = get_int_list_from_file(the_1000_num_gen_file_path)

    assert the_1000_ints == the_1000_ints_from_reference

    # Test 3: state after generating intergers are same
    state_after_1000_gen = get_int_list_from_file(state_after_gen_100_file_path)
    assert r._mt == state_after_1000_gen

    print("All 3 tests pass! The MT19937 seems correctly implemented!")


if "__main__" == __name__:
    test_MT19937()
    print("End of program")
