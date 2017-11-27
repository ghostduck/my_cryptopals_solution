# Use ordered dict because we want to preserve order when encoding to str
from collections import OrderedDict
from secrets import token_bytes
import itertools

from tools.crypto_helper import AES

# increase difficult slightly by using an increasing id, and simulate real world profile creation ...
# but doesn't matter if can solve it within 10 calls of oracle
uid = itertools.count(1)
AES_key_bytes = token_bytes(16)

def decrypt_profile(cipher_bytes):
    """
        Return profile string from encrypted bytes.
    """
    plain_bytes = AES.ECB.decrypt(cipher_bytes=cipher_bytes, key_bytes=AES_key_bytes)
    return plain_bytes.decode(encoding="utf-8")

def encrypt_profile_str(profile_str):
    """
        Return encrypted bytes of the encoded string.
    """
    bytes_to_encrypt = bytes(profile_str, encoding="utf-8")
    cipher_bytes = AES.ECB.encrypt(plain_bytes=bytes_to_encrypt, key_bytes=AES_key_bytes)

    return cipher_bytes

def encrypted_profile_for(email):
    # The blackbox for this challenge.
    encoded_str = profile_to_encoded_str(profile_for(email))
    return encrypt_profile_str(encoded_str)

def sanitize_email(email):
    # Just remove the encoding metacharacter right now to simplify things
    return email.replace("=", "").replace("&", "")

def profile_for(email):
    """
        Create a profile (ordered dict) with a string of email.
        Need to sanitize the email.
    """

    email = sanitize_email(email)
    profile = OrderedDict({
        "email": email,
        "uid": next(uid),
        "role": 'user'
    })

    return profile

def profile_to_encoded_str(profile):
    """
        Encode profile to '&' and '=' separated string.
        Return the encoded string.
    """
    return '&'.join(["{}={}".format(k,v) for k,v in profile.items()])

def parse_cookie_like_string(cookie_str):
    """
        Decode cookie_str, return an ordered dict from '=' and '&' separated string.
        For example: "foo=bar&baz=qux&zap=zazzle" will return
        { "foo":"bar", "baz":"qux", "zap":"zazzle" }
    """
    d = OrderedDict()
    arr = cookie_str.split('&')

    for s in arr:
        # strings of "key=value"

        # Choose one: Force to properly paired (slightly more difficult), or ...
        key, value = s.split('=')
        d[key] = value

        # allow incorrect encoding -- discard malformed strings instead of throwing errors
        # arr = s.split('=')
        # if len(arr) == 2:
        #    d[arr[0]] = arr[1]

    return d

def create_block_start_with_admin():
    # 1st block "email=[anything with length of 10]", 2nd block "admin" + byte 11 * 11 (PKCS7 padding)

    injected_str = "123456789a" + "admin" + bytes([11] * 11).decode("utf-8")
    encrypted_bytes = encrypted_profile_for(injected_str)

    return encrypted_bytes[16:32]

def create_block_end_with_role(last_4_letters):
    # 1st block "email=[10 anything], 2nd block "[4 of anything]&uid=2&role="
    # The reason for 2 blocks: "email=[]&uid=2&role=" can't fit in 1 block
    # NOTE: We rely on the fact that uid only has 1 digit. This function needs to change if the length of uid changes.

    injected_str = "123456789a" + last_4_letters
    encrypted_bytes = encrypted_profile_for(injected_str)

    return encrypted_bytes[16:32]

def create_injected_first_block(email):
    # 1st block "email=[10 anything]" we can fit in any string with length of 10
    if len(email) < 10:
        raise ValueError("Email string needs to have at least 10 bytes/characters")

    # anything longer will be discarded
    encrypted_bytes = encrypted_profile_for(email)

    return encrypted_bytes[0:16]


def ECB_copy_pasta():
    # uncomment to run the parsing test
    # test_str_parsing_correctness()

    # Aim : Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
    #       and the ciphertexts themselves, make a role=admin profile.

    # The only blackbox we have is encrypted_profile_for()
    # email=[injected string,no &, no =]&uid=[start with 1]&role=user
    # email=poor@duck.com&uid=1&role=user

    # To be honset, if we are have to face ALL the below conditions:
    # - enter ONLY normal characters (so padding after "admin" is impossible)
    # - force all '&' '=' pairs to be paired (so odd "&role=" without value will throw error instead of getting ignored),
    # - uid is always fixed (In other words, its length can't be controlled at all. But this way makes padding attack like challenge 12 easier)
    # Then those "&uid=10&role=user" are too short for us and could cause trouble ...

    email_for_the_admin = "duck@email.com" # Not my real email

    # I need to write much more complicated codes if we want to allow any emails to have role of admin
    if len(bytes(email_for_the_admin, encoding="utf-8")) != 14:
        raise ValueError("The forged email of admin must be 14 bytes, don't try non ASCII for this")

    first_10_letters = email_for_the_admin[0:10]
    last_4_letters = email_for_the_admin[10:14]

    # Overall image:
    # b1: "email=[10 characters]"
    # b2:                        "[4 characters]&uid=2&role="
    # b3:                                                    "admin"(with PKCS7 padding)

    b1 = create_injected_first_block(first_10_letters)
    b2 = create_block_end_with_role(last_4_letters)
    b3 = create_block_start_with_admin()

    injected_product = b1 + b2 + b3

    crafted_encoded_str = decrypt_profile(injected_product)
    print("This is the crafted encoded string: {}".format(crafted_encoded_str))

    crafted_profile = parse_cookie_like_string(crafted_encoded_str)
    assert crafted_profile["role"] == "admin"
    print("We did it! We faked a profile with role of admin!")


def test_str_parsing_correctness():
    test_parsing()
    test_encrypted_parsing()

def test_encrypted_parsing():
    test_profile = profile_for("poor@duck.com")
    encoding_str = profile_to_encoded_str(test_profile)

    assert decrypt_profile(encrypt_profile_str(encoding_str)) == encoding_str
    print("Test encrypted string parsing is OK! The string {}".format(encoding_str))

def test_parsing():
    s = "foo=bar&baz=qux&zap=zazzle"
    pro = OrderedDict({
        "foo" : "bar",
        "baz" : "qux",
        "zap" : "zazzle"
    })

    assert parse_cookie_like_string(s) == pro
    assert profile_to_encoded_str(pro) == s
    assert profile_to_encoded_str(parse_cookie_like_string(s)) == s
    print("parsing is working correctly!")

if __name__ == "__main__":
    ECB_copy_pasta()
    print("End of program")
