from random import randint
import time

from tools.random_helper import MT19937

class FakeSystemTime(object):
    def __init__(self, t=None):
        self.fake = True  # Turn on/off no waiting mode -- using fake timestamp and fake actual time
        if t is not None:
            self.fake_actual_time = t
        else:
            self.fake_actual_time = time.time()

    def try_sleep(self, t):
        if self.fake:
            self.fake_actual_time += t
            print("Pretend sleeping for {} seconds. ResidentSleeper zzZzzZ".format(t))
        else:
            time.sleep(t)

    def get_current_time(self):
        if self.fake:
            return self.fake_actual_time
        else:
            return time.time()

st = FakeSystemTime()

def sleep_and_get_first_output():
    # Step 1: Sleep for a random amount of time
    st.try_sleep(randint(40, 1000))

    # Step 2: Wake up, use "current time" as seed to MT19937
    current_time = st.get_current_time()
    seed = int(current_time)

    random_source = MT19937(seed)
    print("Actual seed used is {}".format(seed))

    first_out = random_source.genrand_int32()

    # Step 3: Sleep again
    st.try_sleep(randint(40, 1000))

    # Step 4: return the first number
    return (first_out, seed) # code to cheat -- easier for verification

def crack_seed_from_time():
    output, actual_seed = sleep_and_get_first_output()
    print("output is {} ".format(output))

    latest_current_time = st.get_current_time()

    # Try to find seed from output alone -- given that the seed is a recent UNIX timestamp

    # Seems bruteforce is the best solution if we know it is a "recent" timestamp
    # Only try for 10000 secs at most this time
    for t in range(10000):
        older_time_stamp = int(latest_current_time - t)
        rand_source = MT19937(older_time_stamp)
        first_output = rand_source.genrand_int32()

        if output == first_output:
            # Actually it may be collision ... but quite unlikely
            print("Found the same first output!! {} ".format(first_output))
            print("The timestamp we find is {}".format(older_time_stamp))

            if older_time_stamp == actual_seed:
                print("Everything is correct!!")
                return True
            else:
                print("Oops, same output but not having same seed ... keep trying")

    raise ValueError("Can'f find seed value after trying all the 10000 secs")

if "__main__" == __name__:
    crack_seed_from_time()
    print("End of program")